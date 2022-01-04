
Encryption/decryption:
- Vi bruger libsodiums secretstream til at læse og skrive data.
- Der vælges en chunk-størrelse, som er den størrelse vi vil kryptere sektionen af streamen i. Den kan formentlig med fordel sættes til 4096 bytes for at matche FUSE (se nedenfor).
- 

Read:
- Vi laver "random access" ved at læse hver MAC i filen op til den chunk, som vi forsøger at tilgå. Ud fra disse MACs kan vi beregne noncen.
- I praksis burde det ikke udgøre et stort performance problem, fordi:
    - Filer læses som regel lineært
    - MAC'en er forholdsvis lille og skal ikke dekrypteres
    - SSD'er er gode til at hoppe i data (random IO)

I vores implementation gemmer vi alle tidligere set nonces. Dvs. for at læse en 1 GB fil læses der 244141 chunks, og for hver af disse gemmes en 8 byte nonce. Det kræver knap 2 MB at gemme disse, men det betyder til gengæld, at man kan hoppe i filen uden at tilgå disk for at læse MACs.

Write:
- Vi skriver i den valgte chunk-størrelse (f.eks. 4096 bytes for at matche FUSEs størrelse).
- Alle chunks der ligger bag den skrevne chunk skal læses fra disk, dekrypteres og skrives igen.
- Prepends (skrivning til starten af filen) er worst case scenario.
- Appends kræver maks at 1 chunk skrives igen og det er kun hvis den sidste chunk i filen ikke er komplet. Hvis den sidste chunk er komplet (fylder præcis 4096 bytes) kan den næste chunk appendes uden læsning fra disk. Det er best case scenario.
- Det betyder i værste fald at hvis man bruger 4096 byte blocks og skriver 1 byte ad gangen, så skriver man omkring 8,4 MB per 4096 byte block.

[[[
Måske skal vi undlade nogensinde at putte final tagget på streamen.
Det kan vi formentlig tillade os, fordi størrelsen er kendt på forhånd (i modsætning til hvis man transmitterer streamen over netværket).
Ellers vil man blive ved med at putte final-tagget på efter hver write, for så at skulle gå tilbage og lede det og fjerne det, hvis der kommer et write mere.
]]]


Justeringsmuligheder:
Vi kan vælge hvilke chunk-størrelser vi vil skrive til secretstreamen i.
Det kan være et trade-off mellem read speed (hvor mange MACs der skal læses for at beregne nonce til en given position) og write speed (hvor meget data der skal læses tilbage).
Write speed er primært et problem, hvis der laves mange små writes som er mindre end chunk-størrelsen. F.eks. 1 byte 4096 gange. Der vil man skulle læse hver tidligere skrevet byte tilbage.
Så hvis fuse beder om at få skrevet 4096 bytes, kan vi f.eks. skrive det som 8 x 512 bytes.


Overvejelser ift. FUSE når vi implementerer handlers:
Vi betragter FUSE som en black-box ift. hvordan den kalder handlers. F.eks. gør vi ingen antagelser om hvor store sektioner af en fil den prøver at skrive eller hvorvidt den gør det sekventielt.
Det har betydningen for hvor mange checks og beregner vi skal lave på især position og length argumenter, når vi skal kryptere og dekryptere filer.