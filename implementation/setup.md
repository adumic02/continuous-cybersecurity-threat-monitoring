# Setup - rekreacija laboratorija

Ovaj dokument opisuje kako od nule rekreirati lab okruženje korišteno u projektu _Continuous Cybersecurity Threat Monitoring_. Cilj je da netko drugi, uz ovaj dokument i konfiguracijske datoteke u repozitoriju, može ponoviti sve ključne korake: postavljanje virtualnog okruženja, instalaciju operacijskih sustava, konfiguraciju servisa, generiranje prometa i napada, promatranje detekcija u Security Onionu te izrada sučelja i alerta.

## 1. Preduvjeti

Prije početka potrebno je:

-   Host računalo s dovoljno resursa
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
