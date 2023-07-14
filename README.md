# Antivirus
Checks for malicious internet traffic and urls

Algoritmul e acelasi si pentru rezolvarea din C si pentru rezolvarea din Python
Am realizat urmatoarele functii ajutatoare:

"url_euristic_1" - Primeste ca parametrii un url si un fisier cu domenii malitioase
Functia verifica daca vreunul din domeniile din lista de domenii se regaseste in url. 
Daca da, functia returneaza 1, daca nu, functia returneaza 0

"url_euristic_2" - Primeste ca parametru un url
Functia verifica daca stringul ".exe" se afla in url. Daca da, functia returneaza 1, 
daca nu, functia returneaza 0

"nr_digits" - Primeste ca parametru un url.
Functia calculeaza numarul de numere din url (contor). Returneaza contorul.

"url_euristic_3" - Primeste ca parametru un url.
Functia verifica daca domeniul url-ului contine mai mult de 10% numere (apeland
functia nr_digits ca sa afle cate cifre contine). Daca da, functia
returneaza 1, daca nu, functia returneaza 0.

"url_euristic_4" - Primeste ca parametru un url.
Functia verifica daca domeniul url-ului contine stringul "www". Daca da, functia returneaza
1, daca nu, functia returneaza 0. Am observat ca domeniul url-urilor malitioase incepe cu "www"
(un fel de subdomeniu fals ca sa para legit)

In main:
Pentru fiecare url din fisierul "urls.in" se verifica daca vreuna dintre functiile "url_euristic_1", 
"url_euristic_2", "url_euristic_3", "url_euristic_4" returneaza 1 (adica url-ul e malitios). Daca
da, in fisierul "urls-predictions.out" se printeaza 1, daca nu se printeaza 0.

***********************TASK2***********************

Am realizat urmatoarele functii ajutatoare:

get_index_of_parameter - Primeste ca parametrii un sring "parametru" si un string "antet".
"parametru" este unul dintre componentele analizate ale traficului, iar "antet" reprezinta
totalitatea acestor componente (antetul din fisierul "traffic.in"). Functia returneaza
pozitia parametrului in lista de componente ale antetului.

"traffic_euristic_1" - Primeste ca parametrii o intrare din CSV-ul cu trafic si antetul.
Se apeleaza functia "get_index_of_parameter" ca sa se gaseasca indexul parametrului analizat.
Pentru parametrul "flow_duration", daca numarul de zile, ore sau minute e mai mare de 0,
functia returneaza 1. Daca numarul de secunde e mai mare decat 1, functia returneaza tot 1. 
In rest, functia returneaza 0.

"traffic_euristic_2" - Primeste ca parametrii o intrare din CSV-ul cu trafic si antetul.
Se apeleaza functia "get_index_of_parameter" ca sa se gaseasca indexul parametrului analizat.
Se cauta apoi valoarea parametrului dupa indexul sau.
Pentru parametrul "flow_pkts_payload.avg", se verifica daca valoarea acestuia este diferita de 0.
Daca da, functia returneaza 1, daca nu, functia returneaza 0.

In main:

Pentru fiecare intrare din CSV-ul cu trafic se verifica daca functiile "traffic_euristic_1" si 
"traffic_euristic_2" returneaza simultan 1 (adica traficul face parted dintr-un atac). Daca
da, in fisierul "traffic-predictions.out" se printeaza 1, daca nu se printeaza 0.

