from json import *

dico_os={"Windows NT 10.0": ["windows_10", "windows_server_2016"]
, "Windows NT 6.3": ["windows_8.1","windows_server_2012:r2"]
, "Windows NT 6.2" : ["windows_8","windows_server_2012"]
, "Windows NT 6.1" : ["windows_8", "windows_server_2008:r2"]
, "Windows NT 6.0" : ["windows_vista", "windows_server_2008"]
, "Windows NT 5.2" : ["windows_xp_64 Bits", "windows_server_2003"]
, "Windows NT 5.1" : ["windows_xp"]
, "Windows NT 5.0" : ["windows_2000"]
, "Windows NT 4.0" : ["windows_nt_4.0"]
, "Windows NT 3.51": ["windows_nt_3.51"]
, "Windows NT 3.5" : ["windows_nt_3.5"]
, "Windows NT 3.1" : ["windows_nt_3.1"]
, "Windows Phone" : ["windows_phone"]
, "Ubuntu" : ["ubuntu_linux"]
, "GoogleTV" : ["OS_Google_TV"]
, "SymbOS": ["OS_Symbian_OS"]
, "FreeBSD": ["freebsd"]
, "NetBSD" : ["netbsd"]
, "OpenBSD" : ["openbsd"]
, "Googlebot": ["Robot d'exploration Google"]
, "Chilkat" : ["Chilkat_Software"]
, "iPhone" : ["iphone_os:0"],"iPad": ["ipad_os:0"], "iPod": ["ipod_os:0"]
, "Mac OS X" : ["mac_os_x:0"]
, "Android" : ["android:0"]
, "CrOS": ["google:chrome"]
}

list_os=["iPhone", "iPad", "iPod", "Mac OS X", "Android"]

def get_data():
    with open('nvdcve-1.1-2021.json') as f:
        data = load(f)
    return data

data = get_data()

def search(x, y):
    for i in range (len(y)-len(x)):
        if (y[i:i+len(x)]==x):
            if y[i-2:i] == '*:':
                return (True, True)
            return(True, False)
    return (False, False)

def list_cve(app):
    i = 0
    application = []
    os = []
    vs_os = []
    gen_os = []
    no_vs = replace(app)
    print(no_vs)
    for p in data['CVE_Items']:

        try:
            for y in p['configurations']['nodes']:
                for x in y['cpe_match']:
                    boinf, bosup = '', ''
                    try:
                        boinf = 'versionStartIncluding' + x['versionStartIncluding']
                    except KeyError:
                        pass
                    try:
                        boinf = 'versionStartExcluding: ' + x['versionStartExcluding']
                    except KeyError:
                        pass
                    try:
                        bosup = 'versionEndIncluding' + x['versionEndIncluding']
                    except KeyError:
                        pass
                    try:
                        bosup = 'versionEndExcluding: ' + x['versionEndExcluding']
                    except KeyError:
                        pass

                    tmp = search(app, x['cpe23Uri'])
                    tmp1 = search(no_vs[0], x['cpe23Uri'])
                    tmp2 = search(no_vs[1], x['cpe23Uri'])
                    if tmp[0] and x['vulnerable']:
                        if tmp[1]:
                            application += [[x['cpe23Uri'], p['cve']['CVE_data_meta']['ID'], p['cve']['description']['description_data'][0]['value'], boinf, bosup]]
                        else:
                            os += [[x['cpe23Uri'], p['cve']['CVE_data_meta']['ID'], p['cve']['description']['description_data'][0]['value'], boinf, bosup]]
                    elif tmp1[0] and x['vulnerable']:
                        if tmp1[1]:
                            application += [[x['cpe23Uri'], p['cve']['CVE_data_meta']['ID'], p['cve']['description']['description_data'][0]['value'], boinf, bosup]]
                        else:
                            vs_os += [[x['cpe23Uri'], p['cve']['CVE_data_meta']['ID'], p['cve']['description']['description_data'][0]['value'], boinf, bosup]]
                    elif tmp2[0] and x['vulnerable']:
                        if tmp2[1]:
                            application += [[x['cpe23Uri'], p['cve']['CVE_data_meta']['ID'], p['cve']['description']['description_data'][0]['value'], boinf, bosup]]
                        else:
                            gen_os += [[x['cpe23Uri'], p['cve']['CVE_data_meta']['ID'], p['cve']['description']['description_data'][0]['value'], boinf, bosup]]
        except KeyError:
            print('KEYERROR')
        except IndexError:
            print('IndexERROR')
    #print(i)
    #aff_list(application)
    #aff_list(os)
    #aff_list(vs_os)
    #aff_list(gen_os)
    print(len(application))
    print(len(os))
    print(len(vs_os))
    print(len(gen_os))
    return application, os, vs_os, gen_os

def contains_number(txt):
    for t in txt:
        try:
            int(t)
            return True
        except:
            pass
    return False

def replace(txt):
    print(txt)
    if contains_number(txt):
        if ":" in txt or "_" in txt :
            for i in range(-1, -len(txt), -1):
                if txt[i]==":" or txt[i] =="_":
                    try :
                        int(txt[i-1])
                        return replace(txt[0:i])
                    except :
                        return [txt[0:i]+":*", txt[0:i]+":-"]
        else :
            return [txt+":*", txt + ":-"]
    else :
        return [txt+":*", txt + ":-"]


""" Afficher liste objet """
def aff_list(L):
    for i in L:
        print(i)

def clean(tab):
    for i in range (len(tab)-1):
        taille=len(tab[i])
        tab[i]=tab[i][0:taille-1]
    return tab

with open ('user-agent.txt') as f:
    lis=clean(f.readlines())

#Recherche d'une correspondance entre notre User Agent et les User Agent du fichier "user-agent.txt"
def search_same(useragent, liste):
    for i in range(1,len(liste),2):
        if useragent==liste[i]:
            return liste[i-1]
    return False

#Android : si pas de version retourner android:0 sinon android:version
#Iphone : si pas de version iphone_os:0 sinon iphone_os:version
#Ipad : si pas de version ipad_os:0 sinon ipad_os:version
#MacOS : si pas de version mac_os_x:0 sinon mac_os_x:version

#Si la version de l'OS est indiquée, on la retourne

def return_version(text, key):
    new=text.split(";")
    for n in new :
        if len(key)<=len(n):
            for i in range (len(n)-len(key)):
                if (n[i:i+len(key)]==key):
                    cpt=0
                    ind=0
                    start=0
                    for j in range (len(n)):
                        try :
                            int(n[j])
                            if (cpt==0):
                                start=ind
                                cpt+=1
                            ind+=1
                            if (cpt!=0) and j==(len(n)-1):
                                return n[start:ind]
                        except:
                            if cpt!=0:
                                if n[j] == " " or n[j] == ";":
                                    tmp=""
                                    txt2=n[start:ind]
                                    if "_" in txt2:
                                        for r in range (len(txt2)):
                                            if txt2[r] == "_" :
                                                tmp+="."
                                            else :
                                                tmp+=txt2[r]
                                        return tmp
                                    return n[start:ind]
                            ind+=1
    return False

#Retourne l'OS
def search_dico(dico, text):
    for key in dico.keys():
        for i in range (len(text)-len(key)):
            if (text[i:i+len(key)]==key):
                if key not in list_os:
                    return dico[key]
                else :
                    version=return_version(text, key)
                    if version != False :
                        return [dico[key][0][0:-1]+version]
                    else :
                        return dico[key]
    return False

def extract_info(dico, user):
    start=[]
    end=[]
    cpt=0
    for i in user:
        if i =="(":
            start.append(cpt)
        else :
            if i==")":
                end.append(cpt)
        cpt+=1
    if start:
        info=user[start[0]+1:end[0]]
        return search_dico(dico, info)
    return False

def search_bdd(usag):
    os=search_same(usag, lis)
    print(usag)

    if (os==False):
        info=extract_info(dico_os, usag)
        if (info==False):
            print( "Pas de correspondance")
            application = []
            os = []
            vs_os = []
            gen_os = []
        else :
            print(info)
            for i in info :
                print(i)
                application, os, vs_os, gen_os = list_cve(i)
    else :
        print(os)
        application, os, vs_os, gen_os = list_cve(os)
    print('\n')
    return application, os, vs_os, gen_os


if __name__ == "__main__":

    user1="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36"
    user2="Mozilla/5.0 (iPhone; CPU iPhone OS 14_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1 Mobile/15E148 Safari/604.1"
    user3= "Mozilla/5.0 (Linux; Android 10; SAMSUNG SM-J600FN) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/14.0 Chrome/87.0.4280.141 Mobile Safari/537.36"
    user4 ="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36 Edge/16.16299"
    user5="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36 Edg/86.0.622.56"

    os=search_same(user5,lis)

    if (os==False):
        info=extract_info(dico_os, user5)
        if (info==False):
            print( "Pas de correspondance")
        else :
            print(info)
            for i in info :
                print(i)
                list_cve(i)
    else :
        print(os)
        list_cve(os)
