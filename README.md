# RevList2020
Implementazione del modello RevocationList2020 per la revoca di Verifiable Credentials in IOTA Ledger.<br>
Il modello è qui descritto: https://w3c-ccg.github.io/vc-status-rl-2020/#revocationlist2020credential

# Struttura progetto
1) src/main.rs                                                                                                                                                     Nel main è realizzato un semplice esempio di uso della libreria, con un issuer che genera delle Verifiable Credentials revocabili, ognuna con apposito status.
Procede poi a creare una RevocationList2020 sotto forma di Verifiable Credential ed a pubblicarla sulla Tangle in modo da renderla accessibile ad eventuali verificatori. Viene infine mostrato come avviene la verifica della revoca di una credenziale tramite ricerca della RevocationList corrispondente sulla Tangle.

2) src/lib.rs                                                                                                                                                       La libreria implementa la struct RevocationList2020 attraverso la quale è gestito lo stato di ogni credenziale, attraverso una stringa di bit opportunamente compressa e codificata, come da specifica.

3) src/RevocationList2020Status.rs                                                                                                                               Questo modulo implementa l'oggetto Status così come definito nella specifica, in modo da rendere una VC revocabile.

4) stronghold_file.hold
Stronghold è una libreria software che consente di proteggere qualsiasi tipo di segreto digitale, con la particolarità di rendere possibile l'interazione con
quanto protetto solo attraverso le procedure offerte.
Questo file è uno snapshot criptato, precedentemente creato, che funge da database per le IOTA Identity e le rispettive chiavi private.

# Uso
Prima di testare il progetto, è preferibile modificare l'indice della VC della RevocationList nel main per ridurre il tempo di ricerca della lista più recente.
// let mut index_VC_list = "My_Index";

Dalla directory RL2020, lanciare:   cargo run
Come risultato viene stampato a schermo che la credenziale fornita è stata revocata.

