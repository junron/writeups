import shutil
import tarfile
from os import listdir, remove, rmdir, mkdir
from os.path import isdir, basename, join
from zipfile import ZipFile

# Ensure basepath ends with directory terminator
basePath = "<redacted>"

mkdir(join(basePath, "out"))
while True:
    hasDirectory = False
    files = listdir(basePath)
    for file in files:
        file = basePath + file
        if file.endswith(".tar.bz2"):
            print("Extracted", basename(file))
            tar = tarfile.open(file, 'r:bz2')
            tar.extractall(basePath)
            tar.close()
            remove(file)
        elif file.endswith(".tar.gz"):
            tar = tarfile.open(file, 'r:gz')
            tar.extractall(basePath)
            tar.close()
            remove(file)
            print("Extracted", basename(file))
        elif file.endswith(".zip") or file.endswith("kz3"):
            ZipFile(file).extractall(basePath)
            remove(file)
            print("Extracted", basename(file))

    for file in listdir(basePath):
        file = basePath + file
        if file.endswith(".txt"):
            shutil.move(file, join(basePath, "out"))
        elif isdir(file) and not basename(file) == "out":
            for f in listdir(file):
                shutil.move(join(file, f), basePath)
            hasDirectory = True
            rmdir(file)
    if not hasDirectory:
        break
