# Continuous Cybersecurity Threat Monitoring

Projekt prikazuje kako u izoliranom laboratoriju postaviti i nadzirati mrežno okruženje koje sadrži produkciji slične servise (MySQL i Apache) te na njima demonstrirati stvarne napade. Fokus je na tome kako se ti napadi i anomalije mogu detektirati i analizirati pomoću Security Oniona, Suricate i ELK stacka. Naglasak je na etičkom hakiranju, podešavanju IDS pravila i tumačenju rezultata kroz centralizirano prikupljanje i vizualizaciju logova.

## Pregled projekta

Projekt obuhvaća dizajn virtualne mreže s nadzornim čvorom (Security Onion), aplikacijskim serverom (MySQL + Apache), klijentima i napadačem (Kali). U takvom okruženju generiran je i “normalan” promet (legitimne MySQL i HTTP konekcije) i zlonamjeran promet (nmap skeniranja, Metasploit brute‑force na MySQL, Nikto skeniranje Apachea), kako bi se usporedila detekcija različitih scenarija. Prikupljeni logovi i alerti analizirani su putem ELK stacka i vizualizirani u dashboardima, čime je demonstriran cjelovit proces kontinuiranog nadzora sigurnosnih prijetnji.

## Struktura repozitorija

-   `docs/` – pdf dokumentacija i literatura
-   `implementation/` – konfiguracije i setup koraci
-   `results/` – screenshotovi i sažetak rezultata
-   `presentation/` – prezentacije teorijskog i praktičnog dijela projekta

## Korišteni alati

-   VirtualBox - kreiranje i upravljanje virtualnim mašinama (laboratorijem)
-   Microsoft Word - izrada dokumentacije

## Korišteni operacijski sustavi

-   Security Onion 2.4.190
-   Ubuntu Desktop 24.04.3 LTS
-   Ubuntu Server 24.04.3 LTS
-   Kali Linux 2025.4

## Tim

-   Antonio Dumić - postavljanje virtualnog okruženja i konfiguracija Security Oniona
-   Matko Kekez - generiranje normalnog i mrežnog prometa
-   Zdravko Blažević - postavljanje i korištenje ELK stacka i izrada alert sustava
-   Jakov Glavač - dokumentiranje rezultata i izrada dokumentacije

## Kako rekreirati projekt

U ovom repozitoriju ne postoji programski kod koji se može pokrenuti za automatsku reprodukciju laboratorija. Projekt se temelji na ručno postavljenim virtualnim mašinama. Za rekreiranje okruženja potrebno je preuzeti ISO slike korištenih operacijskih sustava (Security Onion, Ubuntu Desktop/Server, Kali Linux) te instalirati VirtualBox kao platformu za virtualizaciju. Detaljniji koraci za kreiranje VM‑ova, dodjelu mrežnih postavki, instalaciju servisa (MySQL, Apache) i povezivanje sa Security Onionom opisani su [ovdje](implementation/setup.md).
