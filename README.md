# Android Health

[![Scarica per Windows](https://img.shields.io/badge/Scarica%20per%20Windows-x64-0078D4?style=for-the-badge)](https://github.com/RoccoFr7/android-health/releases/latest/download/Android-Health-Portatile-Windows-x64.zip)

Android Health è uno strumento Python per analizzare un telefono Android autorizzato via ADB. La scansione è in sola lettura e produce un report HTML consultabile offline e uno snapshot JSON.

- Inventario di app, permessi e accessi speciali, con misure di RAM, batteria, archiviazione e traffico quando disponibili.
- Confronto locale SHA-256 degli APK base e split con indicatori pubblici o personalizzati.
- Revisione delle app opzionali, con preferenze per profilo e disattivazione reversibile a conferma esplicita.
- Confronto tra due scansioni dello stesso dispositivo.

## Avvio

Servono Python 3.10+ e [Android SDK Platform-Tools](https://developer.android.com/tools/releases/platform-tools). Aggiungi la cartella di ADB al PATH o specifica il percorso con --adb prima del sottocomando. Su Windows viene cercata anche la cartella standard dell’SDK sotto LocalAppData.

Clona il repository o scarica il sorgente. Abilita Debug USB nelle Opzioni sviluppatore, collega il telefono e accetta la richiesta di autorizzazione. Apri un terminale nella cartella del progetto.

### Interfaccia grafica

Su Windows apri gui.pyw con Python, oppure usa il comando seguente. Serve un’installazione Python che includa Tcl/Tk.

    python -m android_health.gui

La finestra rileva i telefoni ADB. Seleziona il dispositivo, premi Scansiona e consulta il riepilogo. Apri report mostra il report completo nel browser locale. Il report e lo snapshot JSON vengono salvati in scansioni, accanto al programma. Da Impostazioni puoi scegliere un’altra cartella, indicare adb.exe oppure caricare un catalogo JSON personalizzato.

La finestra riusa un server ADB locale quando disponibile. L’acquisizione, l’analisi e il report non richiedono Internet o un account.

### Catalogo pubblico

Da Impostazioni, Aggiorna catalogo online scarica UAD-ng. Aggiorna indicatori malware scarica gli hash di stalkerware e watchware pubblicati da [Echap](https://github.com/AssoEchap/stalkerware-indicators) e gli indicatori NoviSpy di [Amnesty International Security Lab](https://github.com/AmnestyTech/investigations/tree/master/2024-12-16_serbia_novispy). L’opzione Aggiorna i cataloghi prima di ogni scansione, inizialmente disattivata, aggiorna entrambi nella sessione corrente. I file catalogo-online.json e indicatori-malware.json restano accanto al programma e sono riutilizzati offline. Se un aggiornamento fallisce, la scansione usa la copia locale disponibile.

Da UAD-ng vengono importate le voci Recommended documentate e abbinate alle app di sistema. Gli indicatori SHA-256 pubblici si uniscono a quelli del catalogo personalizzato. In caso di sovrapposizione prevalgono le voci personalizzate. Il download non trasmette dati del telefono. Gli hash degli APK base e split installati e leggibili sono calcolati sul telefono e confrontati in locale. Sicurezza e il report mostrano separatamente la copertura di base e split, con il nome dello split in caso di corrispondenza. Un esito senza corrispondenze riguarda i soli hash controllati e i campioni presenti nelle fonti.

Per aggiornare da terminale, esegui dalla cartella del programma:

    python -m android_health.catalog
    python -m android_health.catalog --malware

Nel pacchetto portatile Windows puoi usare il runtime incluso con .\runtime\python.exe -m android_health.catalog.

### Disattivazione e ripristino

Dopo una scansione premi Ripulisci… e scegli una scheda. Disattiva se non usi contiene app opzionali che puoi disattivare oppure contrassegnare con Tieni sempre. Tieni mostra le preferenze personali e i componenti per cui serve verificare funzione e dipendenze. Da lì puoi annullare una preferenza. Ripristina mostra gli interventi registrati nel profilo. La RAM PSS è una misura istantanea. Un trattino indica che nessun processo corrispondente è stato misurato.

La scheda Sicurezza è raggiungibile anche dal riepilogo. Ordina per priorità le corrispondenze SHA-256 e le altre evidenze. Tieni sempre rimuove l’app dai suggerimenti di pulizia e lascia intatte le segnalazioni di sicurezza. Le preferenze si salvano localmente per telefono e profilo nel file preferenze-app.sqlite3. Per conservarle quando cambi cartella, porta con te quel file insieme al registro di ripristino. La scheda mostra il numero di indicatori disponibili e l’effettiva copertura degli APK.

La disattivazione interrompe l’uso dell’app e conserva APK e dati. Il registro ripristino-app.json, accanto al programma, permette di ripristinare lo stato precedente dalla stessa finestra dopo una scansione. Conserva questo file. Un pacchetto di sistema può essere collegato ad altre funzioni del telefono. Per misurare l’effetto, ripeti la scansione.

### Riga di comando

    python -m android_health devices
    python -m android_health scan --out prima
    python -m android_health scan --out dopo
    python -m android_health compare prima/snapshot.json dopo/snapshot.json --out confronto

Usa cartelle nuove per ogni esecuzione. Apri report.html nel browser. Con più dispositivi usa --serial. Con un profilo specifico aggiungi --user ID alla scansione.

Per un confronto a riposo, acquisisci due snapshot a circa 24 ore di distanza. Tra le letture lascia il dispositivo con schermo spento, nelle stesse condizioni di rete, senza usarlo né caricarlo. Un collegamento USB con alimentazione rende indisponibile la stima oraria a quell’estremo. Puoi usare [ADB via debug wireless](https://developer.android.com/tools/adb#wireless) già configurato su una rete fidata e mantenere lo stesso identificativo ADB per entrambe le letture.

## Catalogo e segnali

Il catalogo integrato contiene una voce iniziale per illustrare l’identificazione di un’app opzionale di sistema. Usa il file catalogo-esempio.json come formato per costruire un catalogo verificato per modello, build ed esigenze dell’utente. Un catalogo esplicito sostituisce quello integrato e viene unito all’eventuale cache UAD-ng.

    python -m android_health scan --catalog catalogo-esempio.json --out verifica
    python -m android_health report prima/snapshot.json --catalog catalogo-esempio.json --out riclassificato

In packages, ciascun ID ha category e reason. Usa optional_preload per le app opzionali rilevate come app di sistema, bloatware per voci già revisionate e utility per strumenti da valutare. In sha256, usa come chiave il digest minuscolo dell’APK base o split e associa un oggetto con source, che documenta l’origine dell’indicatore. Il catalogo fornito include zero indicatori di malware. Un catalogo con indicatori attiva la lettura degli hash, disponibile anche con --hash-apks. Può richiedere tempo su inventari grandi.

Accessibilità e accesso alle notifiche sono segnali da verificare anche per applicazioni legittime. Per stimare l’impatto di un’app usa insieme PSS, traffico ed energia, tenendo conto dei processi e degli UID condivisi. Il report riporta il codice di salute esposto da Android per la batteria. Per valutarne l’usura serve una misura di capacità o dati specifici del produttore.

## Dati e copertura

- /data misura il filesystem del dispositivo. Dimensioni APK, spazio delle singole app e modelli IA nelle directory private sono fuori dal perimetro di questa versione.
- Batterystats misura contatori Android e stime energetiche, con disponibilità variabile. Il confronto mostra solo UID confrontabili nella stessa epoca dei contatori e con la stessa build. I contatori di rete includono più contesti di esecuzione e non forniscono destinazioni. Un'app comparsa durante l’intervallo può essere stata installata dall’utente, dal sistema o da un altro installatore.
- La RAM per processo è una fotografia. Il report usa la memoria disponibile del kernel per il totale disponibile. Una PSS alta da sola non dimostra un rallentamento.
- L’inventario riguarda un profilo per scansione. I permessi elencati sono concessioni runtime Android leggibili in quel profilo. La corrispondenza SHA-256 riguarda il file esatto presente nel catalogo. La verifica delle firme e delle aree private richiede strumenti dedicati.
- Il report e il JSON contengono l’inventario e i permessi. Restano sul computer. Lo snapshot usa un digest dell’identificativo ADB per associare i confronti.

## Test

    python -m unittest -v

I test usano risposte ADB simulate e si possono eseguire senza un telefono collegato. Report, snapshot, preferenze, cataloghi scaricati e binari portatili sono esclusi dal repository.

Ispirato alla [metodologia DDay](https://www.dday.it/redazione/59587/bloatware-consumi-anomali-abuso-di-ram-tutto-quello-che-lia-ci-puo-dire-di-uno-smartphone). Riferimenti tecnici [ADB](https://developer.android.com/tools/adb) e [dumpsys](https://developer.android.com/tools/dumpsys).
