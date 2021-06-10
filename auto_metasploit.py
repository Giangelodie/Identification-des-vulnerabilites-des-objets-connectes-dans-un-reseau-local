#!/usr/bin/env python
import sys, os
import msfrpc
import time
import msfconsole
from subprocess import *
from threading import Thread
import pyautogui, time

global flag
flag =0   

def run_console():
    """
    Fonction qui lance Metasploit et qui exécute le code du fichier lancement_metasploit.py.

    Parameters
    ----------
    None.

    Returns
    -------
    None.

    """

    Popen(['python3', 'lancement_metasploit.py'])
    run(['msfconsole'])

def shutdown_meta():
    """
    Fonction qui exécute le code du fichier arret_metasploit.py.

    Parameters
    ----------
    None.

    Returns
    -------
    None.

    """
    Popen(['python3', 'arret_metasploit.py'])


def lancement():
    """
    Fonction qui lance Metasploit dans un thread.

    Parameters
    ----------
    None.

    Returns
    -------
    None.

    """
    t=Thread(target=run_console)
    t.start()
    time.sleep(30)
    

def read_console(console_data, num):
    """
    Fonction qui lit les données affichées dans la console et qui les écrit dans un fichier.

    Parameters
    ----------
    console_data : données de la console.
    num : nom donné au fichier en sortie.

    Returns
    -------
    None.

    """
    if "Matching Modules" in console_data['data']:
        with open(num, 'a') as f:
            f.write(console_data['data'])
        #print(console_data['data'])
        flag=0

def read_console2(console_data, num):
    """
    Fonction qui lit les données affichées dans la console et qui les écrit dans un fichier.

    Parameters
    ----------
    console_data : données de la console.
    num : nom donné au fichier en sortie.

    Returns
    -------
    None.

    """
    if "Basic options:" in console_data['data']:
        with open(num, 'a') as f:
            f.write(console_data['data'])
        flag=0

def identify(txt):
    """
    Fonction qui identifie une ligne contenant la chaîne de caractères "PORT".

    Parameters
    ----------
    txt : une chaîne de caractères.

    Returns
    -------
    True si la chaîne de caractères comporte le mot "PORT".
    False sinon.

    """
    p="PORT"
    if p in txt[0:4] :
        return True
    else :
        return False

def extract_ip(txt):
    """
    Fonction qui identifie une adresse IP dans une chaîne de caractères.
    
    Parameters
    ----------
    txt : chaîne de caractères.

    Returns
    -------
    Une adresse IP.

    """
    tmp=''
    for i in txt :
        if i !="'" and i !=" ":
            tmp+=i
    for i in range (len(tmp)):
        if tmp[i]=='[':
            start=i
        else :
            if tmp[i]==']':
                end=i
    return tmp[start+1:end].split(",")

def version_loc(tab):
    """
    Fonction qui indique à quelle ligne et à partir de quel caractère de la ligne se trouve la version.

    Parameters
    ----------
    tab : un tableau contenant les informations extraites à partir de la commande nmap.

    Returns
    -------
    [result, result2] : -result = numéro de la ligne
                        -result2 = index du caractère à partir duquel se trouve la version.
    False : si on ne trouve pas la version.

    """
    result1=[]
    result2=[]
    result= {}
    key=[]
    vers="VERSION"
    for t in range (len(tab)) :
        if t==0:
            tab_tmp=extract_ip(tab[t])
            for r in tab_tmp:
                result[r]=[]
            #print(result)
            for k in result.keys():
                key.append(k)
            #print(key)
        if identify(tab[t])==True :
            for i in range (len(tab[t])-len(vers)):
                if tab[t][i:i+len(vers)]==vers:
                    result1.append(i)
                    result2.append(t)
    #print(result1, result2)
    if len(result1)!=0:
        for k in range(len(key)) :
            result[key[k]]=result1[k]
    else :
        return False
    return [result, result2]

def clean_version (ver):
    """
    Fonction qui ne prend pas en compte des informations entre parenthèses dans une version.

    Parameters
    ----------
    ver : un dictionnaire ayant pour clé une adresse IP et pour valeurs les versions associées à cette adresse IP.

    Returns
    -------
    La même dictionnaire mais avec des versions débarassées des informations entre parenthèses.

    """
    dic_tmp={}
    for k, v in ver.items():
        dic_tmp[k]=[]
        for i in v :
            start=0
            for j in range (len(i)):
                if i[j]== "(":
                    start=j
            if start==0:
                dic_tmp[k].append(i)
            else :
                dic_tmp[k].append(i[0:start-1])
    return dic_tmp

def version(tab, res):
    """
    Fonction qui permet d'extraire les versions associées à une adresse IP.

    Parameters
    ----------
    tab : données extraites de l'affichage de la commande nmap.
    res : une sortie de la fonction version_loc.

    Returns
    -------
    Un dictionnaire ayant pour clé une adresse IP et pour valeurs les versions associées à cette adresse IP.

    """
    result={}
    key=[]
    dic=res[0]
    inter=res[1]
    
    for k in dic.keys():
        key.append(k)
    for k in key :
        result[k]=[]
    cpt=0
    for i in range(len(inter)):
        start=inter[i]
        if i==len(inter)-1:
            end=len(tab)
        else :
            end=inter[i+1]
        new=tab[start:end]
        for n in new :
            if "open" in n or "filtered" in n or "closed" in n or "unfiltered" in n or "open|filtered" in n or "closed|filtered" in n:
                try:
                    if n[int(dic[key[cpt]]):-1] != '':
                        result[key[cpt]].append(n[int(dic[key[cpt]]):-1])
                except :
                    pass
        cpt+=1
    #return clean_version(result)
    return result
    
def flag_test():
    """
    Fonction qui permet de tester si la console est encore occupée.

    Parameters
    ----------
    None

    Returns
    -------
    None

    """
    cpt_flag=0
    while not flag:
        cpt_flag +=1
        time.sleep(2)
        if cpt_flag>10 :
            break
    if cpt_flag <= 10:
        flag_test()
            
def clean_tab(tab):
    """
    Fonction qui permet de nettoyer un tableau des caractères inutiles.

    Parameters
    ----------
    tab : un tableau.

    Returns
    -------
    Un tableau nettoyé de ses caractères inutiles.

    """
    tmp=[]
    for t in tab :
        if t!='':
            tmp.append(t)
    return tmp

def ret_exploit(tab):
    """
    Fonction qui permet d'extraire les exploits associés à une adresse IP.

    Parameters
    ----------
    tab : une ligne

    Returns
    -------
    Une liste contenant les exploits associés à une adresse IP.
    False si on n'en trouve pas.

    """
    result=[]
    for ta in tab :
        new=clean_tab(ta.split(" "))
        try:
            int(new[0])
            result.append(new[1])
        except :
            pass  
    if len(result)==0:
        return False
    return result

def exploit(liste):
    """
    Fonction qui permet d'extraire les exploits associés à des adresses IP.

    Parameters
    ----------
    liste : données extraites de l'affichage de la commande search.

    Returns
    -------
    Un dictionnaire contenant les exploits associés à une adresse IP.

    """
    result={}
    for l in liste :
        with open(l, "r") as f :
            tab=f.readlines()
        if ret_exploit(tab) == False :
            return False
        result[l]=ret_exploit(tab)
    return result

def infos(of):
    """
    Fonction qui permet d'extraire le nom, la description et les références de chaque exploit.

    Parameters
    ----------
    of : nom du fichier contenant les données extraites suite à l'exécution de la commande info.

    Returns
    -------
    Une liste de listes des informations de chaque exploit.

    """
    Descriptions = []
    Names = []
    References = []
    a=[]
    result=[]

    start =0
    end =0
    start1=0
    end1=0
    endref=0
    of = open(of,"rb")
    for index, line in enumerate(of):
        if b'Name:' in line:
            Names.append(line.decode('utf-8').strip())
        if b'Description:' in line:
            start = index
        if b'References:' in line:
            end = index
            start1=index
            endref=index
        if b'Name:' in line:
            end1=index

         #Add Desciption lines into b
        a.append(line.decode('utf-8').strip())
        b = ''.join(a[start:end])
        if b == "":
            continue
        if b not in Descriptions:
            Descriptions.append(b)
            
        #Add References lines into c
        c = ''.join(a[start1:end1])
        if c == "":
            continue
        if c not in References:
            References.append(c)

    References.append(''.join(a[endref:]))

    for i in range (len(Names)) :
        tmp=[Names[i], Descriptions[i], References[i]]
        result.append(tmp)

    return result
     
def ip_metasploit(list_ip):
    """
    Fonction qui permet d'extraire les vulnérabilités et leurs informations de chaque adresse IP que nous passons en paramètre.

    Parameters
    ----------
    list_ip : liste des adresses IP que nous voulons analyser

    Returns
    -------
    Une liste de listes des informations de chaque exploit pour chaque adresse IP.

    """

    path="nmap_result.txt"
    
    with open("nmap_result.txt",'w') as f:
        f.write(str(list_ip)+'\n')
        
    # Create a new instance of the Msfrpc client with the default options
    username="msf"
    msf_pass="pres"
    client = msfrpc.MsfRpcClient(password=msf_pass, token=username)
    
    #Create a console

    res = client.call('console.create')
    console_id = res['id']
    
    print("\n-----Starting Nmap scan-----\n")
    
    for l in list_ip :
            command="nmap -oN " + path + " -sV --append-output " + l + " -Pn" + "\n"
            print(command)
            a = client.call('console.write', [console_id,command])
        
    while True:
        res = client.call('console.read',[console_id])
        if len(res['data']) > 1:
            print ("In process....")
        if res['busy'] == True:
            time.sleep(1)
            continue
        break
       
    with open("nmap_result.txt",'r') as f:
        tab=f.readlines()
    

    if version_loc(tab)== False :
        print("\nCannot do Nmap scan on this Ip address..\n")
        if len(tab)>1:
            if "All 1000 scanned ports" in tab[4]:
                return ["Pas de failles détectées"]
            else :
                return []
        else :
            return []
    else :
        dic_version=version(tab, version_loc(tab))
        dic_vers_key=dic_version.keys()
    
    #print(dic_version)
    
    cleanup = client.call('console.destroy',[console_id])
    print ("Cleanup result: %s" %cleanup['result'])
    
    '''PARTIE SEARCH'''
    
    print("\n-----Search exploits-----\n")
    
    consoles=[]
    for k in dic_vers_key:
        with open(k, "w") as f:
            f.write('')
        console=msfconsole.MsfRpcConsole(client, cb=read_console, num=k)
        consoles.append(console)
        for l in dic_version[k] :
            command="search " + l + "\n"
            print(command)
            e=console.execute(command)
            flag=1
    
    flag_test()
 
    for c in consoles :
        c.__del__()
        
    if exploit(dic_vers_key)== False :
        print("\nCannot find any exploits..\n")
        return ["Pas de failles détectées"]
    dic_exploit=exploit(dic_vers_key)
    
    #print(dic_exploit)
    
    '''PARTIE INFO'''
    
    print("\n-----Exploits informations-----\n")

    consoles2=[]
    for k in dic_vers_key:
        name=k + "_info"
        with open(name, "w") as f:
            f.write('')
        consol=msfconsole.MsfRpcConsole(client, cb=read_console2, num=name)
        consoles2.append(consol)
        for l in dic_exploit[k] :
            command="info " + l + "\n"
            print(command)
            e=consol.execute(command)
            
    flag_test()
    
    for c in consoles2 :
        c.__del__()
    
    for k in dic_vers_key:
        name=k + "_info"
        info=infos(name)
    name1=list_ip[0]
    name2=list_ip[0]+"_info"
    if os.path.exists(name1):
        os.remove(name1)
    else:
        print("\nImpossible de supprimer le fichier car il n'existe pas\n")
    if os.path.exists(name2):
        os.remove(name2)
    else:
        print("\nImpossible de supprimer le fichier car il n'existe pas\n")
    
    return info
'''
lancement()     
print(ip_metasploit(['192.168.0.78']))
shutdown_meta()'''