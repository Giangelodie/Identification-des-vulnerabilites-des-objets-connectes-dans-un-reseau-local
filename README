Tout d’abord, avant de lancer le programme, il faut installer Metasploit. A l’aide de la
commande à copier coller sur un terminal qui se trouve : https://github.com/rapid7/
metasploit-framework/wiki/Nightly-Installers [27].
Puis il faut lancer le Metasploit à l’aide de la commande : msfconsole sur un terminal.
taper : yes
taper : root
taper : fgh

Lorsque vous avez cet affichage vous pouvez fermer le terminal, Metasploit est installé.
Ensuite, il faut s’assurer d’avoir installé différents packages comme :
- pymetasploit3
- nmap
- pyatogui
- pyshark
- subprocess
A l’aide de la commande dans un terminal : pip3 install "nom_package"

Pour finir, il faut avoir téléchargé tous les fichiers python suivant dans le même réper-
toire :
- interface.py
- identifications.py
- lancement_metasploit.py
- arret_metasploit.py
- auto_metasploit.py
- search_os.py
- msfconsole.py
- msfrpc.py
Ainsi que les bases de données json :
- macaddress.io-db.json [1]
- nvdcve-1.1-2021.json [25]
Et le fichier : user-agent.txt

Pour lancer le programme, il suffit d’ouvrir un terminal, de se positionner dans le ré-
pertoire contenant tous les fichiers cités précédemment et de taper la commande :
python3 interface.py

L’interface va s’ouvrir et vous proposer soit de faire une capture en live du trafic avec la
durée de cette capture à indiquer, soit d’ouvrir un fichier .pcapng déjà existant et d’en préciser le chemin.
Puis si la configuration est celle de notre conception, il faut ajouter l’adresse MAC du
point d’accès et cocher la case AP.
Pour finir, il faut cliquer sur start, ne plus cliquer ailleurs et attendre.
