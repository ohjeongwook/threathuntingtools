import os
import zipfile
        
def LocateFile(filename):
    paths=[]
    paths.append('.')
    telemetry_root=os.getenv('TELEMETRY_ROOT')
    if telemetry_root!=None:
        paths.append(telemetry_root)

    paths.append(r'..\Data')
    paths.append(r'..\..\Data')
    paths.append(r'..\Data\Telemetry')
    paths.append(r'..\..\Data\Telemetry')

    for path in paths:
        full_pathname=os.path.join(path, filename)
    
        if os.path.isfile(full_pathname):
            if zipfile.is_zipfile(full_pathname):
                zip_ref = zipfile.ZipFile(full_pathname, 'r')
                filename_creation = os.path.getctime(full_pathname)
                for name in zip_ref.namelist():
                    print('Checking '+name)
                    extracted_filename=os.path.join(os.getcwd(), name)
                    
                    extract=True
                    if os.path.isfile(extracted_filename):
                        extracted_filename_creation = os.path.getctime(extracted_filename)
                    
                        if filename_creation < extracted_filename_creation:
                            extract=False
                            
                    if extract:
                        print('Extracting '+name)
                        zip_ref.extract(name)
                    else:
                        print('Using existing '+name)
                    break
                zip_ref.close()
                return extracted_filename
                
            return full_pathname
        
    return filename