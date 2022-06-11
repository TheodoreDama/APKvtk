import os
# !/usr/bin/python
import json
import os
import sys
import ntpath
import time
import re
# import urlparse, urllib2
import hashlib
from threading import Thread
import traceback
import requests

# import for web scaping
import logging
import scrapy
from scrapy.crawler import CrawlerProcess


class bcolors:
    TITLE = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    INFO = '\033[93m'
    OKRED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    BGRED = '\033[41m'
    UNDERLINE = '\033[4m'
    FGWHITE = '\033[37m'
    FAIL = '\033[95m'

#************************************ commune
rootDir = os.path.expanduser("~") + "/.APKEnum/"  # ConfigFolder ~/.SourceCodeAnalyzer/

gmapURLs = ["https://maps.googleapis.com/maps/api/staticmap?center=45%2C10&zoom=7&size=400x400&key=",
                    "https://maps.googleapis.com/maps/api/streetview?size=400x400&location=40.720032,-73.988354&fov=90&heading=235&pitch=10&key=",
                    "https://www.google.com/maps/embed/v1/place?q=Seattle&key=",
                    "https://www.google.com/maps/embed/v1/search?q=record+stores+in+Seattle&key=",
                    "https://maps.googleapis.com/maps/api/directions/json?origin=Disneyland&destination=Universal+Studios+Hollywood4&key=",
                    "https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key=",
                    "https://maps.googleapis.com/maps/api/distancematrix/json?units=imperial&origins=40.6655101,-73.89188969999998&destinations=40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524%7C40.6860072%2C-73.6334271%7C40.598566%2C-73.7527626%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524%7C40.6860072%2C-73.6334271%7C40.598566%2C-73.7527626&key=",
                    "https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum%20of%20Contemporary%20Art%20Australia&inputtype=textquery&fields=photos,formatted_address,name,rating,opening_hours,geometry&key=",
                    "https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Bingh&types=%28cities%29&key=",
                    "https://maps.googleapis.com/maps/api/elevation/json?locations=39.7391536,-104.9847034&key=",
                    "https://maps.googleapis.com/maps/api/timezone/json?location=39.6034810,-119.6822510&timestamp=1331161200&key=",
                    "https://roads.googleapis.com/v1/nearestRoads?points=60.170880,24.942795|60.170879,24.942796|60.170877,24.942796&key="]

apktoolPath = "./Dependencies/apktool.jar"
##################################################
# Regex of

androidPermission = "(android\.permission\.[A-Z\_]*)"
androidPackage = "(package=\"[a-z\_\.]*\")"
androidAppName = "app_name\">[a-z A-Z\_\.]*<"
urlRegex = '(http|ftp|https)://([\w_-]+(?:(?:\.[\w_-]+)+):?\d*)([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?'  # regex to extract domain
s3Regex1 = "https*://(.+?)\.s3\..+?\.amazonaws\.com\/.+?"
s3Regex2 = "https*://s3\..+?\.amazonaws\.com\/(.+?)\/.+?"
s3Regex3 = "S3://(.+?)/"
s3Website1 = "https*://(.+?)\.s3-website\..+?\.amazonaws\.com"
s3Website2 = "https*://(.+?)\.s3-website-.+?\.amazonaws\.com"
publicIp = "https*://(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(?<!172\.(16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31))(?<!127)(?<!^10)(?<!^0)\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(?<!192\.168)(?<!172\.(16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31))\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(?<!\.255$))"
gMapsAPI = "(AIzaSy[\w-]{33})"


def myPrint(text, type):
    if (type == "INFO"):
        print(bcolors.INFO + bcolors.BOLD + text + bcolors.ENDC + "\n")
        return
    if (type == "INFO_WS"):
        print(bcolors.INFO + bcolors.BOLD + text + bcolors.ENDC)
        return
    if (type == "PLAIN_OUTPUT_WS"):
        print(bcolors.INFO + text + bcolors.ENDC)
        return
    if (type == "ERROR"):
        print(bcolors.BGRED + bcolors.FGWHITE + bcolors.BOLD + text + bcolors.ENDC)
        return
    if (type == "MESSAGE_WS"):
        print(bcolors.TITLE + bcolors.BOLD + text + bcolors.ENDC)
        return
    if (type == "MESSAGE"):
        print(bcolors.TITLE + bcolors.BOLD + text + bcolors.ENDC + "\n")
        return
    if (type == "INSECURE"):
        print(bcolors.OKRED + bcolors.BOLD + text + bcolors.ENDC + "\n")
        return
    if (type == "INSECURE_WS"):
        print(bcolors.OKRED + bcolors.BOLD + text + bcolors.ENDC)
        return
    if (type == "OUTPUT"):
        print(bcolors.OKBLUE + bcolors.BOLD + text + bcolors.ENDC + "\n")
        return
    if (type == "OUTPUT_WS"):
        print(bcolors.OKBLUE + bcolors.BOLD + text + bcolors.ENDC)
        return
    if (type == "SECURE_WS"):
        print(bcolors.OKGREEN + bcolors.BOLD + text + bcolors.ENDC)
        return
    if (type == "SECURE"):
        print(bcolors.OKGREEN + bcolors.BOLD + text + bcolors.ENDC + "\n")
        return


def isNewInstallation():
    if (os.path.exists(rootDir) == False):
        myPrint("Thank you for installing APKvtk1", "OUTPUT_WS")
        os.mkdir(rootDir)
        return True
    else:
        return False


def isValidPath(apkFilePath):
    global apkFileName
    myPrint("I: Checking if the APK file path is valid.", "INFO_WS")
    if (os.path.exists(apkFilePath) == False):
        myPrint("E: Incorrect APK file path found. Please try again with correct file name.", "ERROR")
        print
        exit(1)
    else:
        myPrint("I: APK File Found.", "INFO_WS")
        apkFileName = ntpath.basename(apkFilePath)


def printList(lst):
    counter = 0
    for item in lst:
        counter = counter + 1
        entry = str(counter) + ". " + item
        myPrint(entry, "PLAIN_OUTPUT_WS")


def reverseEngineerApplication(apkFileName):
    global projectDir
    myPrint("I: Initiating APK decompilation process", "INFO_WS")
    projectDir = rootDir + apkFileName + "_" + hashlib.md5().hexdigest()

    if (os.path.exists(projectDir) == True):
        myPrint(
            "I: The APK is already decompiled. Skipping decompilation and proceeding with scanning the application.",
            "INFO_WS")
        return projectDir
    os.mkdir(projectDir)
    myPrint("I: Decompiling the APK file using APKtool.", "INFO_WS")
    result = os.system(
        "java -jar " + apktoolPath + " d " + "--output " + '"' + projectDir + "/apktool/" + '"' + ' "' + apkFilePath + '"' + '>/dev/null')
    if (result != 0):
        myPrint(
            "E: Apktool failed with exit status " + str(result) + ". Please try updating the APKTool binary.",
            "ERROR")
        print
        #exit(1)
    myPrint("I: Successfully decompiled the application. Proceeding with scanning code.", "INFO_WS")

    #print("Reverse results*******", result)  # debug
    #print("type of this: ", type(result))  # debug


# sys.exit()

def findS3Bucket(line):
    temp = re.findall(s3Regex1, line)
    if (len(temp) != 0):
        for element in temp:
            s3List.append(element)

    temp = re.findall(s3Regex2, line)
    if (len(temp) != 0):
        for element in temp:
            s3List.append(element)

    temp = re.findall(s3Regex3, line)
    if (len(temp) != 0):
        for element in temp:
            s3List.append(element)


def findGoogleAPIKeys(line):
    temp = re.findall(gMapsAPI, line)
    if (len(temp) != 0):
        for element in temp:
            gmapKeys.append(element)


# def findUnrestrictedGmapKeys():
# 	response=[]
# 	for key in gmapKeys:
# 		for url in gmapURLs:
# 			try:
# 				response = requests.get(url+key)
# 			except requests.exceptions.ConnectionError as e:
# 				myPrint("I: Connection error while finding network calls","INFO")
# 			except:
# 				continue
# 		if response.status_code == 200:
# 				unrestrictedGmapKeys.append(key)
# 		continue

def findAndroidPermission(line):
    temp = re.findall(androidPermission, line)
    if (len(temp) != 0):
        for element in temp:
            androidPermissionList.append(element)


def findAndroidPackageName(line):
    temp = re.findall(androidPackage, line)
    if (len(temp) != 0):
        for element in temp:
            element = element.replace('package=\"', '')
            element = element.replace('\"', '')
            print("Package name: ***",element)
            androidPackageNameList.append(element)
        #findAndroidDescription(element)


def findAndroidDescription(apkPackageName):
    # *************** web scraping ******************************************************
    print("Scrapy description***: ",apkPackageName)
    class GooglePlayStoreDescribSpider(scrapy.Spider):
        start_urls = ["https://play.google.com/store/apps/details?id=" + apkPackageName + "&hl=fr&gl=US"]
        custom_settings = {
            'LOG_LEVEL': logging.WARNING,
        }
        print("Scrapy Class")

        def parse(self, response):
            print("respponse: ", response.status)
            if (response.status == 200):

                # result =response.css('div.DWPxHb >span > div') #rugle  bARER
                result = response.css('div.bARER')  # after update of google play
                describ = result.get()
                # print("describ befor:", describ)
                # Clean the data
                # print("Object descript: ", describ)
                # describ = describ.replace('<div jsname=\"sngebd\">', '') #befor update
                describ = describ.replace('<div class="bARER">', '')
                describ = describ.replace('<br>', ' ')
                describ = describ.replace('</div>', ' ')
                print("describ after:", describ)
                androidAppDescriptionList.append(describ)
                return describ
            else:
                print("Invalid app ID on google playStore")
                print("describ after:", response.css('div.bARER'))

    #  yield {
    #     'number': describ.strip()
    # }
    process = CrawlerProcess(
        {'USER_AGENT': 'DAMA Theodore, App description'}
    )
    process.crawl(GooglePlayStoreDescribSpider)
    process.start()


# *************** end of web scraping ******************************************************

def findAndroidAppName(line):
    temp = re.findall(androidAppName, line)
    if (len(temp) != 0):
        for element in temp:
            element = element.replace('app_name\">', '')
            element = element.replace('<', '')
            androidAppNameList.append(element)


def findS3Website(line):
    temp = re.findall(s3Website1, line)
    if (len(temp) != 0):
        for element in temp:
            s3WebsiteList.append(element)

    temp = re.findall(s3Website2, line)
    if (len(temp) != 0):
        for element in temp:
            s3WebsiteList.append(element)


def findUrls(line):
    temp = re.findall(urlRegex, line)
    if (len(temp) != 0):
        for element in temp:
            authorityList.append(element[0] + "://" + element[1])
            if (scopeMode):
                for scope in scopeList:
                    if scope in element[1]:
                        inScopeAuthorityList.append(element[0] + "://" + element[1])


def findPublicIPs(line):
    temp = re.findall(publicIp, line)
    if (len(temp) != 0):
        for element in temp:
            publicIpList.append(element[0])


def performRecon():
    global domainList, authorityList, inScopeDomainList, inScopeAuthorityList
    filecontent = ""

    print("Perform function")



    for dir_path, dirs, file_names in os.walk(rootDir + apkFileName + "_" + hashlib.md5().hexdigest()):
        for file_name in file_names:
            try:
                fullpath = os.path.join(dir_path, file_name)
                fileobj = open(fullpath, mode='r')
                filecontent = fileobj.read()
                fileobj.close()

                if (file_name == 'AndroidManifest.xml'):
                    # Extraction of Permission and package name
                    findAndroidPackageName(filecontent)
                    findAndroidPermission(filecontent)
                if (file_name == 'strings.xml'):
                    # extraction of app_name
                    findAndroidAppName(filecontent)

            except Exception as e:
                myPrint("E: Exception while reading " + fullpath, "ERROR")

            try:
                # findUrls(filecontent)
                # findPublicIPs(filecontent)
                # findS3Bucket(filecontent)
                # findS3Website(filecontent)
                # findGoogleAPIKeys(filecontent)
                # findUnrestrictedGmapKeys()
                t1 = Thread(target=findUrls, args=(filecontent,))
                t2 = Thread(target=findPublicIPs, args=(filecontent,))
                t3 = Thread(target=findS3Bucket, args=(filecontent,))
                t4 = Thread(target=findS3Website, args=(filecontent,))
                t5 = Thread(target=findGoogleAPIKeys, args=(filecontent,))
                t1.start()
                t2.start()
                t3.start()
                t4.start()
                t5.start()
                t1.join()
                t2.join()
                t3.join()
                t4.join()
                t5.join()
            # t6 = Thread(target=findUnrestrictedGmapKeys, args=())
            # t6.start()
            # t6.join()
            except Exception as e:
                myPrint("E: Error while spawning threads", "ERROR")
    #print("PermissionList:", androidPermissionList)
    #print("app_name: ", androidAppNameList[0])
    #print("package name:", androidPackageNameList[0])


def displayResults():
    global inScopeAuthorityList, authorityList, s3List, s3WebsiteList, publicIpList, gmapKeys, unrestrictedGmapKeys, androidPermissionList, androidPackageNameList, androidAppNameList, androidAppDescriptionList, apkHash256, apkHashmd5
    inScopeAuthorityList = list(set(inScopeAuthorityList))
    authorityList = list(set(authorityList))
    s3List = list(set(s3List))
    s3WebsiteList = list(set(s3WebsiteList))
    publicIpList = list(set(publicIpList))
    gmapKeys = list(set(gmapKeys))
    unrestrictedGmapKeys = list(set(unrestrictedGmapKeys))

    androidPermissionList = list(set(androidPermissionList))
    androidPackageNameList = list(set(androidPackageNameList))
    androidAppNameList = list(set(androidAppNameList))
    print("androidPackage name: ",androidPackageNameList[0])
    androidAppDescriptionList = findAndroidDescription(androidPackageNameList[0]) # list(set(androidAppDescriptionList))
    apkHash256=apkHash256
    apkHashmd5=apkHashmd5

    # for stockage in a Json file
    data = {"urls": authorityList,
            "s3buckets": s3List,
            "s3websites": s3WebsiteList,
            "ips": publicIpList,
            "googleMapApi": gmapKeys,
            "permissions": androidPermissionList,
            "packageName": androidPackageNameList[0],
            "appName": androidAppNameList[0],
            "appDescription": androidAppDescriptionList,
            "hash256":apkHash256,
            "hashmd5":apkHashmd5}
    file_name=apkHash256+"_APKvtk"+".json"
    with open(file_name, "w") as write_file:
        json.dump(data, write_file,indent=4, sort_keys=True)

    print("**** data", data)

    if (len(authorityList) == 0):
        myPrint("\nNo URL found", "INSECURE")
    else:
        myPrint("\nList of URLs found in the application", "SECURE")
        printList(authorityList)

    if (scopeMode and len(inScopeAuthorityList) == 0):
        myPrint("\nNo in-scope URL found", "INSECURE")
    elif scopeMode:
        myPrint("\nList of in scope URLs found in the application", "SECURE")
        printList(inScopeAuthorityList)

    if (len(s3List) == 0):
        myPrint("\nNo S3 buckets found", "INSECURE")
    else:
        myPrint("\nList of in S3 buckets found in the application", "SECURE")
        printList(s3List)

    if (len(s3WebsiteList) == 0):
        myPrint("\nNo S3 websites found", "INSECURE")
    else:
        myPrint("\nList of in S3 websites found in the application", "SECURE")
        printList(s3WebsiteList)

    if (len(publicIpList) == 0):
        myPrint("\nNo IPs found", "INSECURE")
    else:
        myPrint("\nList of IPs found in the application", "SECURE")
        printList(publicIpList)

    if (len(gmapKeys) == 0):
        myPrint("\nNo Google MAPS API Keys found", "INSECURE")
    else:
        myPrint("\nList of Google Map API Keys found in the application", "SECURE")
        printList(gmapKeys)
    # if (len(unrestrictedGmapKeys)==0):
    # 	myPrint("\nNo Unrestricted Google MAPS API Keys found", "INSECURE")
    # 	return
    # myPrint("\nList of Unrestricted Google Map API Keys found in the application", "SECURE")
    # printList(unrestrictedGmapKeys)

    print("")


directory =r'.'
#sample_files = [doc for doc in os.listdir() if doc.endswith('.apk')]
#print('sample: ',sample_files)
#sample_contents=[]
#data_apks_sha256_name=set()

################################################################################
## For each APK, we generate more information about it
##############################################################################
for filename in os.listdir(directory):
    if filename.endswith('.apk'):

        ##***********************************************************************************************************************************************

        projectDir = ""
        apkFilePath = ""
        apkFileName = ""
        apkHash = ""
        scopeMode = False

        scopeList = []
        # my contribution list
        androidApkHash256List = []
        androidApkHashMd5List = []
        androidPermissionList = []
        androidPackageNameList = []
        androidAppNameList = []
        androidAppDescriptionList = []

        authorityList = []
        inScopeAuthorityList = []
        publicIpList = []
        s3List = []
        s3WebsiteList = []
        gmapKeys = []
        vulnerableGmapKeys = []
        unrestrictedGmapKeys = []
        apkHash256=""
        apkHashmd5=""

        # ******************************************** Hash

        sha256_hash = hashlib.sha256()
        md5_hash = hashlib.md5()
        with open(filename, "rb") as f:
            # Read and update hash string value in blocks of 4K
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
                md5_hash.update(byte_block)
            apkHash256 = sha256_hash.hexdigest()
            apkHashmd5 = md5_hash.hexdigest()
            # print(sha256_hash.hexdigest())
            print("Sha256: ", apkHash256)
            print("md5 :", apkHashmd5)



        ############################################## test

        ####################################################################################################

        ####################################################################################################


        apkFilePath = filename
        apkFileName=filename
        print("apkFilePath :", apkFilePath)
        try:
            isNewInstallation()
            isValidPath(apkFilePath)
            print("file path:", apkFilePath)
            print("file name:", apkFileName)
            reverseEngineerApplication(apkFileName)
            performRecon()
            displayResults()
        except KeyboardInterrupt:
            myPrint("I: Acknowledging KeyboardInterrupt. Thank you for using APKvtk1", "INFO")
            #exit(0)
        myPrint("Thank You For Using APKvtk1", "OUTPUT")


        #print("file",filename)