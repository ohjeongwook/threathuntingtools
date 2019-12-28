#!/usr/bin/env python
# coding: utf-8

import os
import time
import re
import sqlite3
import pickle
import io
import traceback
    
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
import numpy as np
from scipy.sparse import csr_matrix, save_npz, load_npz
import sparse_dot_topn.sparse_dot_topn as ct
import yaml

import file_util

class StringMatcher:
    def __init__(self):
        self.Clusters = {}

    def load_data(self, filename, data_type = 'String', data_format = 'csv', table_name = 'Default', column_name = 'Default', lower_case = False):
        filename = file_util.locate_file(filename)
        
        pd.set_option('display.max_colwidth', -1)
        if data_format == 'yml':
            with open(filename, 'r', encoding = 'utf8') as fd:
                data = yaml.safe_load(fd)
                self.Data = pd.DataFrame(data, columns = [column_name]) 
            print(self.Data.head())            
        if data_format == 'csv':
            self.Data = pd.read_csv(filename)
        elif data_format == 'pkl':
            self.Data = pd.read_pickle(filename)
        elif data_format == 'sqlite':
            con = sqlite3.connect(filename)
            self.Data = pd.read_sql_query("SELECT %s from %s" % (column_name, table_name), con)
            con.close()

        self.DataType = data_type
        self.LowerCase = lower_case
        self.load_target_data(column_name)
        
    def add_strings(self, command_lines, column_name = 'Default', data_type = 'String', lower_case = False):
        self.Data = pd.DataFrame(data = {column_name: command_lines})
        self.DataType = data_type
        self.LowerCase = lower_case
        self.load_target_data(column_name)

    def load_target_data(self, column_name):
        if self.LowerCase:
            self.TargetData = self.Data[column_name].str.lower()
        else:
            self.TargetData = self.Data[column_name]        

    def print_data_head(self):
        print('The shape: %d x %d' % self.Data.shape)
        print(self.Data.head())
        
    def get_data_count(self):
        return self.Data.count()

    def trim_data(self, start, end):
        self.Data = self.Data.iloc[start:end]

    def ngrams(self, string, n = 3):
        if self.DataType == 'String':
            string = re.sub(r'[, -./]|\sBD', r'', string)
            ngrams = zip(*[string[i:] for i in range(n)])
            return [''.join(ngram) for ngram in ngrams]
        elif self.DataType == 'FilePath':
            return re.split(r'[\\/]+', string)
        elif self.DataType == 'CommandLine':
            replaced_string = re.sub("[0-9]{1, 3}\.[0-9]{1, 3}\.[0-9]{1, 3}\.[0-9]{1, 3}", "<normalized_ip>", string)
            replaced_string = re.sub("[\w\-. ]+\.tmp", "<normalized_filename>", replaced_string)
            replaced_string = re.sub("test_user_[a-fA-F0-9]+", "<normalized_path>", replaced_string)
            return re.sub(r"[A-Za-z]:\\[a-zA-Z0-9_+\\~\.]+", "<normalized_path>", replaced_string)

    def get_tfidf_matrix(self):
        vectorizer = TfidfVectorizer(min_df = 1, analyzer = self.ngrams)
        return vectorizer.fit_transform(self.TargetData)
        
    def perform_consine_similarity_analysis(self, A, B, ntop, lower_bound = 0):
        # force A and B as a CSR matrix.
        # If they have already been CSR, there is no overhead
        A = A.tocsr()
        B = B.tocsr()
        M, _ = A.shape
        _, N = B.shape

        idx_dtype = np.int32

        nnz_max = M*ntop

        indptr = np.zeros(M+1, dtype = idx_dtype)
        indices = np.zeros(nnz_max, dtype = idx_dtype)
        data = np.zeros(nnz_max, dtype = A.dtype)

        ct.sparse_dot_topn(
            M, N, np.asarray(A.indptr, dtype = idx_dtype), 
            np.asarray(A.indices, dtype = idx_dtype), 
            A.data, 
            np.asarray(B.indptr, dtype = idx_dtype), 
            np.asarray(B.indices, dtype = idx_dtype), 
            B.data, 
            ntop, 
            lower_bound, 
            indptr, indices, data)

        return csr_matrix((data, indices, indptr), shape = (M, N))
    
    def analyze(self, threshold = 0.8):       
        t1 = time.time()
        tf_idf_matrix = self.get_tfidf_matrix()
        self.SimilarityMatrix = self.perform_consine_similarity_analysis(tf_idf_matrix, tf_idf_matrix.transpose(), 10, threshold)
        t = time.time() - t1
        print("Elapsed seconds:", t)

    def _get_matches(self, top = None):
        non_zeros = self.SimilarityMatrix.nonzero()

        sparserows = non_zeros[0]
        sparsecols = non_zeros[1]

        if top:
            nr_matches = top
        else:
            nr_matches = sparsecols.size

        left_side = np.empty([nr_matches], dtype = object)
        right_side = np.empty([nr_matches], dtype = object)
        similarity = np.zeros(nr_matches)

        for index in range(0, nr_matches):
            left_side[index] = self.TargetData[sparserows[index]]
            right_side[index] = self.TargetData[sparsecols[index]]
            similarity[index] = self.SimilarityMatrix.data[index]

        return pd.DataFrame({'left_side': left_side, 
                              'right_side': right_side, 
                               'similarity': similarity})

    def get_matches(self, size = None):
        self.MatchesDF = self._get_matches(top = size)
        #self.MatchesDF = self.MatchesDF[self.MatchesDF['similarity'] < 0.99999] # Remove all exact matches
        return self.MatchesDF
    
    def get_match_count(self):
        return self.MatchesDF.count()
    
    def cluster(self):
        non_zeros = self.SimilarityMatrix.nonzero()

        sparserows = non_zeros[0]
        sparsecols = non_zeros[1]
        cluster_indexes = [None] * len(self.TargetData)

        self.Clusters = {}
        next_cluster_index = 0
        for index in range(0, sparsecols.size):
            left_index = sparserows[index]
            rigth_index = sparsecols[index]
            if cluster_indexes[left_index] == None and cluster_indexes[rigth_index] == None:
                cluster_index = cluster_indexes[left_index] = cluster_indexes[rigth_index] = next_cluster_index

                self.Clusters[cluster_index] = {}
                self.Clusters[cluster_index][left_index] = 1
                self.Clusters[cluster_index][rigth_index] = 1

                next_cluster_index += 1
            elif cluster_indexes[left_index] == None:
                cluster_index = cluster_indexes[left_index] = cluster_indexes[rigth_index]
                
                self.Clusters[cluster_index][left_index] = 1
            elif cluster_indexes[rigth_index] == None:
                cluster_index = cluster_indexes[rigth_index] = cluster_indexes[left_index]
                
                self.Clusters[cluster_index][rigth_index] = 1
       
    def dump_clusters(self, filename_prefix = r'clusters\custer-'):
        dir_name = os.path.dirname(filename_prefix)
        
        if not os.path.isdir(dir_name):
            try:
                os.makedirs(dir_name)
            except:
                pass
               
        if not os.path.isdir(dir_name):
            print("Can't create cluster ouput folder")
            return

        for (cluster_index, data_indexes) in self.Clusters.items():
            with io.open(filename_prefix+'-%.5d-%.5d.txt' % (len(data_indexes), cluster_index), "w", encoding = "utf-8") as fd:
                for data_index in data_indexes:
                    fd.write('-'*80+'\n')
                    fd.write(self.TargetData[data_index])
                    fd.write('\n')
                    fd.write('\n')

    def get_cluster_with_size(self, cluster_size):
        cluster_indexes = []
        for (cluster_index, data_indexes) in self.Clusters.items():
            if len(data_indexes) == cluster_size:
                cluster_indexes.append(cluster_index)
        return cluster_indexes

    def get_cluster_data_indexes(self, cluster_index):
        if not cluster_index in self.Clusters:
            return []
        
        return self.Clusters[cluster_index]

    def get_cluster_data(self, cluster_index):
        if not cluster_index in self.Clusters:
            return []
        
        data_indexes = self.Clusters[cluster_index]
        data_list = []
        for data_index in data_indexes:
            data_list.append(self.TargetData[data_index])
        return data_list

    def get_cluster_counts(self):
        cluster_counts = []
        for (cluster_index, data_indexes) in self.Clusters.items():
            cluster_counts.append([cluster_index, len(data_indexes)])
        return cluster_counts

    def save_clusters(self, filename):
        self.make_directories(filename)
        pickle.dump(self.Clusters, open(filename, "wb" ))
        
    def load_clusters(self, filename):        
        self.Clusters = pickle.load(open(filename, "rb" ))

    def save_similarity_matrix(self, filename):
        self.make_directories(filename)
        save_npz(filename, self.SimilarityMatrix)
        
    def load_similarity_matrix(self, filename, column_name = 'Default'):
        self.TargetData = self.Data[column_name]
        self.SimilarityMatrix = load_npz(filename)

    def make_directories(self, filename):
        dir_name = os.path.dirname(filename)
        
        if not os.path.isdir(dir_name):
            try:
                os.makedirs(dir_name)
            except:
                traceback.print_exc()
