from tkinter import *
from identification import *
from auto_metasploit import *
from tkinter.font import *

def affichage_eth(L):
    """
    Fonction qui produit un string contenant toutes les informations des
    différents appareils Ethernets .

    Parameters
    ----------
    L : Liste des appareils Ethernets.

    Returns
    -------
    String des informations des appareils Ethernets.

    """
    affichage = ''
    for app in L:
        flag_ip = 0
        str = '\nAdresse MAC: ' + app[0]
        # print(str)
        i = 1
        while i < len(app):
            if app[i][0] == 'ip' and not flag_ip:
                str += '\nAdresse IP: ' + app[i][1]
                flag_ip = 1
            elif app[i][0] == 'ip' and  flag_ip:
                str += ', ' + app[i][1]
            elif app[i][0] == 'cst':
                str += '\nConstructeur: ' + app[i][1]
            elif app[i][0] == 'hn':
                str += '\nHost Name: ' + app[i][1]
            elif app[i][0] == 'ssdp':
                str += '\nInformation venant du protocole UPnP:\nFichier: ' + app[i][1] + '\n'
                for inf in app[i][2]:
                    str += inf + ', '
            elif app[i][0] == 'UA':
                str += '\nUser-Agent: ' + app[i][1]
                if app[i][2][1] == [] and app[i][2][2] == [] and app[i][2][3] == [] and app[i][2][4] == []:
                    str += "\nPas assez d'informations pour déterminer des failles."
                else:
                    # print(app[i][2])
                    if app[i][2][2] != []:
                        str += "\n\nFAILLES POUR L'OS PRÉCIS:\n "
                        for y in app[i][2][2]:
                            for x in y:
                                if x != '':
                                    str += '\n' + x
                            str += '\n-----------------------------------'
                        str += '\n-----------------------------------'
                    if app[i][2][3] != []:
                        str += "\n\nFAILLES POUR DES VERSIONS D'UN CERTAIN INTERVAL DE CET OS:\n "
                        for y in app[i][2][3]:
                            for x in y:
                                if x != '':
                                    str += '\n' + x
                            str += '\n-----------------------------------'
                        str += '\n-----------------------------------'
                    if app[i][2][4] != []:
                        str += "\n\nFAILLES POUR CET OS SANS VERSION:\n "
                        for y in app[i][2][4]:
                            for x in y:
                                if x != '':
                                    str += '\n' + x
                            str += '\n-----------------------------------'
                        str += '\n-----------------------------------'
                    if app[i][2][1] != []:
                        str += "\n\nFAILLES POUR DES APPLICATIONS SOUS CET OS:\n "
                        for y in app[i][2][1]:
                            for x in y:
                                if x != '':
                                    str += '\n' + x
                            str += '\n-----------------------------------'
                str += '\n'
            elif app[i][0] == 'ms':
                str += '\nExécution de MetaSploit: '
                if type(app[i][1]) == list:
                    if len(app[i][1]) == 1 or app[i][1] == []:
                        str += '\nPas de failles trouvées après scan'
                    else:
                        for exp in app[i][1]:
                            for ch in exp:
                                str += '\n' + ch
                            str += '\n'
                else:
                    str += '\nPas de failles trouvées après scan'
            i += 1
        str += '\n\n'
        affichage += str
    return affichage


def affichage_http(app):
    """
    Fonction qui produit un string contenant toutes les informations HTTP des
    appareils WIFI.

    Parameters
    ----------
    app : Liste des informations HTTP des appareils WIFI.

    Returns
    -------
    String des informations HTTP des appareils WIFI.

    """
    affichage = ''
    i = 1
    while i < len(app):
        str = ''
        str += '\nUser-Agent: ' + app[i][0]
        # print(app[i][1][0])
        if app[i][1][0] == [] and app[i][1][1] == [] and app[i][1][2] == [] and app[i][1][3] == []:
            str += "\nPas assez d'informations pour déterminer des failles."
        else:
            # print(app[i][2])
            if app[i][1][1] != []:
                str += "\n\nFAILLES POUR L'OS PRÉCIS:\n "
                for y in app[i][1][1]:
                    for x in y:
                        if x != '':
                            str += '\n' + x
                    str += '\n-----------------------------------'
                str += '\n-----------------------------------'
            if app[i][1][2] != []:
                str += "\n\nFAILLES POUR DES VERSIONS D'UN CERTAIN INTERVAL DE CET OS:\n "
                for y in app[i][1][2]:
                    for x in y:
                        if x != '':
                            str += '\n' + x
                    str += '\n-----------------------------------'
                str += '\n-----------------------------------'
            if app[i][1][3] != []:
                str += "\n\nFAILLES POUR CET OS SANS VERSION:\n "
                for y in app[i][1][3]:
                    for x in y:
                        if x != '':
                            str += '\n' + x
                    str += '\n-----------------------------------'
                str += '\n-----------------------------------'
            if app[i][1][0] != []:
                str += "\n\nFAILLES POUR DES APPLICATIONS SOUS CET OS:\n "
                for y in app[i][1][0]:
                    for x in y:
                        if x != '':
                            str += '\n' + x
                    str += '\n-----------------------------------'
        str += '\n'
        i += 1
        str += '\n\n'
        affichage += str
    return affichage


def affichage_ssdp(app):
    """
    Fonction qui produit un string contenant toutes les informations SSDP des
    appareils WIFI.

    Parameters
    ----------
    app : Liste des informations SSDP des appareils WIFI.

    Returns
    -------
    String des informations SSDP des appareils WIFI.

    """
    affichage = ''
    i = 1
    while i < len(app):
        str = '\nInformation venant du protocole UPnP:\nFichier: ' + app[i][1] + '\n'
        for inf in app[i][2]:
            str += inf + ', '
        str += '\n'
        affichage += str
        i += 1
    return affichage


def exec_meta(L):
    """
    Fonction qui appelle le lancement de Metasploit, appalle le scan de chaque
    appareil puis appelle l'arrêt de Metasploit.

    Parameters
    ----------
    L : Liste des appareils Ethernets.

    Returns
    -------
    Liste des appareils Ethernets incrémentée des failles trouvées par
    Metasploit.

    """
    lancement()
    time.sleep(13)
    for app in L:
        i = 1
        while i < len(app):
            tmp = []
            if app[i][0] == 'ip' and len(app[i][1]) <= 15:
                tmp = ip_metasploit([app[i][1]])
                if tmp != []:
                    break
            i += 1
        app += [['ms', tmp]]
    shutdown_meta()
    return L


def audit():
    """
    Fonction qui récupère les paramètres indiqués sur l'interface pour lancer
    l'analyse puis afficher les résultats de celle-ci sur l'interface.

    Parameters
    ----------
    None.

    Returns
    -------
    None.

    """
    text1.delete(1.0, 'end')
    text1.insert(0.0, "En cours d'éxecution...", 'charg')
    # text1.tag_config('titre', font=helv36)
    text1.update()
    if AP.get():
        acces_point = add_ap.get()
    else:
        acces_point = 0
    if int(svRadio.get()) == 1:
        text1.insert(2.0, '\nCapture du réseau...', 'charg')
        text1.update()
        cap_tshark(int(timer.get()))
        file = 'file_audit.pcap'
    else:
        file = path.get()
    text1.insert(3.0, '\nExtraction des informations des trames...', 'charg')
    text1.update()
    L, Ldhcp, Lhttp, Lssdp = extract_trame(file, acces_point)
    text1.insert(4.0, '\nRecherche de failles...', 'charg')
    text1.update()
    L, Lhttp = comp_ua_bdd(Lhttp, L)
    text1.insert(5.0, '\nMetasploit...', 'charg')
    text1.update()
    L = exec_meta(L)
    text1.delete(1.0, 'end')
    text1.insert(0.0, 'OBJETS ETHERNETS:\n\n' + affichage_eth(L) + '\nOBJETS WIFI UTILISANT HTTP: \n\n' + affichage_http(Lhttp) + '\nOBJETS WIFI UTILISANT SSDP: \n\n' + affichage_ssdp(Lssdp))
    text_tag('Attributs', 'Adresse', 0.12)
    text_tag('Attributs', 'Constructeur', 0.13)
    text_tag('Attributs', 'Host Name', 0.11)
    text_tag('Attributs', 'User-Agent', 0.11)
    text_tag('Attributs', 'Exécution de', 0.91)
    text_tag('cve', 'CVE', 0.16)
    text_tag('titre', 'OBJETS', 0.31)
    text_tag('faille', 'FAILLES', 0.91)
    text_tag('pasfailles', 'Pas assez', 0.91)
    text_tag('pasfailles', 'Pas de failles', 0.91)
    text_tag('cpe', 'cpe', 0.91)


def text_tag(tag, mot, taille):
    tmp = 0.0
    tmp1 = -1.0
    while tmp != '':
        tmp = text1.search(mot, tmp)
        if tmp != '':
            if float(tmp) < tmp1:
                break
            tmp = float(tmp)
            text1.tag_add(tag, tmp, tmp + taille)
            text1.tag_add('valeurs', tmp + taille, tmp +1.0)
            tmp += taille
            tmp1 = tmp



root = Tk()
root.title("Application de détection des vulnérabilités des objets connectés")
root.geometry("700x550")
root.minsize(500,300)
# root.config(background="gray60")
# root.config(background="#973D3D")
# Frame capture
frame = LabelFrame(root, bd = 4, labelanchor = 'nw', text = 'Choix du type de capture', bg="white")
frame.pack(side = 'top', fill = 'x')

# Bouton live
svRadio = StringVar()
svRadio.set('1')
Radiobutton(frame, text='Capture en live', bg="white", variable=svRadio, value='1').pack(side = 'left')
# Entry durée capture
timer = StringVar()
timer.set('durée en seconde')
ent_timer = Entry(frame, textvariable=timer)
ent_timer.pack(side = 'left')

# Bouton file
file = IntVar()
Radiobutton(frame, text="Capture provenant d'un fichier",bg="white", variable=svRadio, value='2').pack(side = 'left')
# Entry chemin fichier
path = StringVar()
path.set('Chemin vers le fichier')
ent_path = Entry(frame, textvariable=path)
ent_path.pack(side = 'left')

# Frame AP
frame2 = LabelFrame(root, bd = 4, labelanchor = 'nw', text = "Point d'Accès", bg="white")
frame2.pack(side = 'top')
# Bouton AP
AP = IntVar()
cb_ap = Checkbutton(frame2, anchor = 'e', text = 'AP',bg="white", variable = AP)
cb_ap.pack(side = 'left')
# Entry adresse mac AP
add_ap = StringVar()
add_ap.set('@MAC AP')
ent_ap = Entry(frame2, textvariable=add_ap)
ent_ap.pack(side = 'left')

# Frame Bouton
frame3 = Frame(root)
frame3.pack(side = 'top')
# Bouton Start
bt_start = Button(frame3, bd = 3, bg="white", text = 'Start', command= lambda:audit())
bt_start.pack()


# Frame Bouton
frame4 = Frame(root)
frame4.pack(side = 'top')
# Scrollbar
scrollbar = Scrollbar(frame4)
text1 = Text(frame4, yscrollcommand=scrollbar.set)
scrollbar.config(command=text1.yview)
scrollbar.pack(side='right', fill='y')
text1.pack(side='left', expand=0, fill='both')
ch = Font(family='Times New Roman', size=13, weight='bold', underline=0)
ch0 = Font(family='Times New Roman', size=12)
ch1 = Font(family='Helvetica', size=12, slant='italic')
ch2 = Font(family='Times New Roman', size=12, weight='bold')
ch3 = Font(family='Times New Roman', size=12, underline=1)
ch4 = Font(family='Times New Roman', size=12, underline=1)
ch5 = Font(family='Times New Roman', size=12, slant='italic')
ch6 = Font(family='Times New Roman', size=10)
text1.tag_config('Attributs', font=ch)
text1.tag_config('valeurs', font=ch0)
text1.tag_config('charg', font=ch1, foreground="#973D3D")
text1.tag_config('cve', font=ch2)
text1.tag_config('titre', font=ch3)
text1.tag_config('faille', font=ch4)
text1.tag_config('pasfailles', font=ch5)
text1.tag_config('cpe', font=ch6, foreground="gray25")

mainloop()
