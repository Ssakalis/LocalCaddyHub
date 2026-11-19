# Sicherheitsreparaturen, November 2026 – Teil 1

Ausgangsstand dieses Branches: `63e905c1ccb527cedf4f3e66d0deb778720d3d32` (aktueller Checkout bei Arbeitsbeginn; kein Reset). Implementiert im bestehenden Checkout auf `fix/security-review-part1`. Keine produktiven Dienste, Konten, Zertifikate oder Speicherverzeichnisse wurden für Tests verwendet. Alle HTTP-Dienste und Testdaten liegen lokal in temporären Verzeichnissen; Schlüssel und Zugangsdaten sind synthetisch.

Implementierungscommits: `c091721` (F01, Routing und reale Proxy-Regressionen) und `293ab00` (Konfigurations-, Zertifikats-, Session- und TOTP-Integrität einschließlich UI und Regressionstests).

## F01 – Zugriffsschutz vor der Weiterleitung

**Ursache/Funktionen:** `writeSiteBlock()` gab Site-ACLs neben `handle` aus. Caddy sortierte `handle` vor `respond`/`abort`. Zusätzlich konnte `redir` innerhalb eines Handlers ACLs und Basic Auth überholen.

**Korrektur:** Eine explizite `route` führt Domain- bzw. geerbte/zusätzliche Subdomain-ACLs vor dem Dispatch aus. Ein verschachteltes `handle` erhält Caddys Pfadsortierung. Jeder Pfadhandler besitzt eine explizite Route mit WAF, ACL, Basic Auth und anschließend Proxy/Redirect. `handle_path` behält seine Präfixentfernung.

**Regression:** `tests/proxy.test.cjs` prüft mit dem echten Custom-Caddy erlaubte Anfragen und Backend-Aufrufzähler bei gesperrten Domain-, Subdomain- und Handler-Anfragen. Abgedeckt sind 403, abort, Allow/Deny/invertierte Listen, Vererbung, zusätzliche Subdomain-Listen, mehrere Handler, Pfadspezifität, Redirect, Basic Auth und WAF. Generatorprüfungen in `tests/caddy_generator.test.js` ergänzen die Laufzeitprüfung.

**Prüfung/Ergebnis:** Generator und vollständiger Proxy-Gate ausgeführt; Ergebnisse siehe Prüfprotokoll unten.

**Einschränkung:** Bereits ausgerollte strukturierte Caddyfiles müssen bewusst neu gespeichert und angewendet werden. Beliebige Raw-Dateien werden nicht umgeschrieben.

## F02/F03 – Raw-Dateien und referenzierte Schlüssel

**Ursache/Funktionen:** `setTlsKeyType()` und `clearCertificateReferencesForFiles()` erzeugten unabhängig vom tatsächlichen Caddyfile neue Konfiguration aus SQLite. `certificateReferenceRows()` kannte nur strukturierte Datenbankreferenzen; der Löschpfad prüfte Raw-Verwendungen nicht.

**Korrektur:** Die neue SQLite-Tabelle `config_state` speichert Modus, SHA-256-Dateifingerprint und Version. Zertifikatsaktionen, die Konfiguration erzeugen, verlangen einen nachweislich strukturierten Stand. Unbekannte Legacy-Dateien und extern geänderte Dateien gelten als Raw. Eine automatische verlustbehaftete Übernahme findet nicht statt. Bei einer fehlgeschlagenen RSA-Runtime-Aktualisierung werden Datei, Schlüsselauswahl und Metadaten wiederhergestellt, sofern zwischenzeitlich keine fremde Konfiguration installiert wurde; fremde Änderungen werden geschützt.

Der Löschpfad prüft zusätzlich Raw-Datei und statische Imports in `src/rawReferences.js`, benutzt die echte Caddy-Adaption und schützt direkte Pfade, Symlink-/Hardlink-Aliase und Verzeichnis-Loader. Nicht sicher auflösbare Umgebungsplatzhalter, dynamische Loader und Imports werden vor einer Dateimutation mit 409 abgewiesen. Importinhalt und relevante Pfadidentitäten werden nach der Adaption und unmittelbar vor dem Entfernen erneut geprüft. Referenzentfernung und Dateiverschiebung werden mit der geprüften Konfigurationsänderung verbunden; bei Fehlschlag bleibt die ursprüngliche Datei erhalten. Regulär nachweislich unbenutzte Dateien bleiben löschbar.

Der unabhängige Review ergänzte konkrete Randfälle: Auch extensionlose Schlüsselaliase, einfache Verzeichnisnamen, normalisierte strukturierte Pfade wie `./selected.pem` und Inode-Aliase werden geschützt. Dateiname und Snippetname bei Imports dürfen nicht mehrdeutig sein. Subdomain-`customCert` wird jetzt in SQLite gespeichert, migriert, erneut erzeugt und bei der Referenzbereinigung berücksichtigt; zuvor konnte der Generator dieses API-Feld verwenden, obwohl die Speicherung es verwarf. Ein ungültiges Legacy-Modell verhindert das Lesen einer gültigen Raw-Datei nicht. RSA-Rollbacks verwenden die innerhalb der Schreibtransaktion erfasste Revision, stellen ursprüngliche Datei-Abwesenheit wieder her und rufen keinen möglicherweise defekten Validator auf.

Generator und Referenzprüfung verwenden dieselbe Behandlung von Backslashes und Unterverzeichnissen. Nach der asynchronen Validierung werden fehlende Dateien und die genaue Menge passender Referenzen erneut geprüft: Ein zwischenzeitlicher Upload oder Aliaswechsel lässt die Bereinigung vor der Mutation mit 409 scheitern. Echte verzögerte SQLite-Fremdschlüsselfehler prüfen auch COMMIT-Fehler. Scheitert sogar der Rücksetz-COMMIT, wird der zuletzt konsistente installierte Zustand beibehalten und 500 gemeldet; es wird keine ältere Datei mit neueren Datenbankwerten kombiniert. Bei solchen Speicher-/Datenbankfehlern ist die gemeldete Aktion administrativ zu prüfen.

Ein weiterer echter HTTP-Test veröffentlicht während eines fehlgeschlagenen DELETE-Rollbacks einen neuen privaten Schlüssel per Upload. Die Wiederherstellung ersetzt diesen erfolgreichen Upload nicht: atomisches Verknüpfen verweigert einen inzwischen belegten Namen, erhält beide Dateien und meldet 409 samt Name der aufbewahrten alten Datei. Ohne Namenskonflikt wird die alte Datei wiederhergestellt und die private Zwischenkopie entfernt.

**Regression:** `tests/config_integrity.test.cjs` prüft Raw-RSA/Referenzbereinigung ohne Änderungen, Raw-referenzierte Schlüssel, unbenutzte Dateien, externe Änderungen, Legacy-Erkennung, gemeinsame Revisionen, fehlgeschlagenen Reload und Transaktionsfehler. `tests/rawReferences.test.cjs` prüft echte Caddy-Adaption, statische Imports/Snippets, verschachtelte Umgebungsreferenzen, dynamische Imports, Verzeichnis-Loader, Aliase, Importänderungen und Pfadwechsel. `tests/backend.test.cjs` erhält die bisherigen Upload-/Rollback-Prüfungen.

**Prüfung/Ergebnis:** Isolierte HTTP-/SQLite-Tests sowie echte Adaption mit dem Custom-Caddy; siehe Prüfprotokoll.

**Einschränkungen:** Import-Globs, Importargumente, rekursive/wiederholte oder mehr als 64 Imports sowie mehrdeutige Escapes und mehrzeilige Literale werden konservativ geschützt. Vor einer solchen Löschung sind Raw-Referenzen manuell zu prüfen und zu entfernen. Frühere Generatorversionen können ohne Metadaten als Raw erkannt werden; der gespeicherte strukturierte Entwurf bleibt erhalten und kann nach bewusster Bestätigung das Raw-Caddyfile ersetzen. Externe Dateischreiber müssen für koordinierte Änderungen den API-Vertrag verwenden; ein fremder Schreibvorgang exakt während einer Dateiumbenennung ist ohne gemeinsame Dateisperre nicht vollständig koordinierbar. Ein Fehler beim endgültigen Entfernen einer bereits unreferenzierten Datei kann eine private `.deleted-*`-Sicherungsdatei zurücklassen und wird protokolliert.

## F06 – Gemeinsamer Konfigurations- und Revisionsvertrag

**Ursache/Funktionen:** Vollersetzungen über `/api/config/structured` und `/api/config` wurden lediglich serialisiert. Der Server wusste nicht, auf welchem gelesenen Stand ein Entwurf beruhte.

**Korrektur/Vertrag für Teil 2/3:**

- GET `/api/config/structured` und GET `/api/config` liefern dieselbe starke `ETag`-Revision und `X-Config-Mode: structured|raw`; die bisherigen JSON-Formate bleiben erhalten. `Cache-Control: no-store` verhindert die Nutzung veralteter zwischengespeicherter Verwaltungsdaten.
- Die Revision bindet persistierte Version/Modus, tatsächlichen Caddyfile-Inhalt und das vollständige strukturierte Modell. Externe Datei- und Datenbankänderungen ändern deshalb die Revision auch ohne vorausgegangenen API-Schreibzugriff.
- POST auf beide Konfigurationsrouten, RSA-Umstellung, Referenzbereinigung und DELETE mit `removeReferences=1` verlangen exakt diese Revision als `If-Match`. Fehlend: 428; veraltet: 412; unsichere Modusumwandlung: 409. `If-Match: *` umgeht die Vorbedingung nicht.
- Strukturierte Vollersetzungen im Raw-Modus benötigen zusätzlich `X-Config-Mode: structured`. Die produktive Oberfläche setzt dieses Signal ausschließlich nach ausdrücklicher Bestätigung, dass das vorhandene Raw-Caddyfile ersetzt wird. Raw-Save setzt den Modus Raw. Zertifikatsaktionen besitzen diese Umwandlungsmöglichkeit nicht.
- Prüfung erfolgt innerhalb der Schreibwarteschlange und nochmals nach der Caddy-Validierung in der unmittelbaren SQLite-Schreibtransaktion. Modell, Metadaten und Dateiersetzung werden gemeinsam abgeschlossen oder zurückgesetzt. Ein abgewiesener Schreibzugriff ändert weder Modell noch Datei noch Revision. Ein erfolgreicher Konfigurationsschreibzugriff liefert die neue ETag zurück.
- Die Schreibantwort liefert genau die innerhalb ihrer Transaktion erfasste Revision, auch wenn danach eine externe Änderung stattfindet. Eine spätere Änderung wird niemals zum Rollback-Ziel eines früheren Schreibzugriffs.
- Die UI bindet `configRevision` an genau den geladenen strukturierten Entwurf. Ein separat geladener Raw-Anzeigetext ersetzt diese Basisrevision nicht. Ein Konflikt erhält Entwurf und ursprüngliche Revision; es erfolgt kein automatisches Laden oder Zusammenführen der Serverantwort.
- **Wichtig für Teil 3:** Ein reiner Zertifikats-Reload verändert weder Entwurf noch Basisrevision und erzeugt serverseitig keine neue Konfigurationsrevision. Auch RSA/Referenzaktionen laden den lokalen Entwurf nicht neu und setzen dessen Basisrevision nicht auf die neue Serverrevision. Nach einer solchen Konfigurationsänderung muss der Anwender seine lokalen Änderungen bewusst sichern, neu laden und abgleichen. Ein nachfolgender Save mit der alten Basis erhält 412.

**Regression:** Zwei Clients laden denselben Stand, A ergänzt eine Domain, B ändert ein anderes Feld mit alter Revision: 412 und As Domain bleibt erhalten. Ergänzend: fehlende Vorbedingungen aller Schreibaktionen, gemeinsame Raw-/RSA-/Cleanup-Revisionen, Konflikt ohne Teiländerung, externe Änderung während Validierung, Datenbankfehler und Rollback. `tests/ui.test.cjs` und die echten Browser-/API-Flows prüfen Header, Raw-Bestätigung und Entwurfserhalt; ein Zertifikats-Reload war bereits korrekt vom Entwurf getrennt und ist nun ausdrücklich durch einen Regressionstest belegt.

**Prüfung/Ergebnis:** API-, Backend-, UI- und reale Proxy-/API-Validierungstests; siehe Prüfprotokoll.

**Kompatibilität:** Externe API-Clients müssen vor dem Schreiben lesen und `If-Match` mitsenden. Bestehende SQLite-Modelle, Zertifikate, Schlüssel und Konten bleiben bestehen. Ein neuer Browser-Reload aktualisiert den JavaScript-Client.

## F07 – Begrenzter, speicherbarer JSON-Roundtrip

**Ursache/Funktionen:** Der globale Express-Parser lehnte oberhalb 100 KiB ab. `structuredConfigFromDb()` expandiert kompakte Eingaben um die gespeicherten/defaulteten Felder; die zurückgelieferte Darstellung war deshalb nicht wieder speicherbar.

**Korrektur:** Ausschließlich Konfigurations-JSON bekommt vor dem globalen Parser eine Grenze von **2.097.152 UTF-8-Bytes (2 MiB)**. Dies reicht für ungefähr 1.500 vollständig expandierte normale Handler. Zusätzlich wird innerhalb der Speichertransaktion die tatsächliche normalisierte GET-Darstellung auf dieselbe Grenze geprüft. Auch die erzeugte Raw-JSON-Darstellung `{content: ...}` wird vor dem Schreiben begrenzt: mehrfach verwendete ACLs können beim Generieren stark expandieren. Ein kompakter POST, der bei einem der beiden GETs über diese Grenze wachsen würde, erhält 413 und wird vollständig zurückgerollt. Andere JSON-Endpunkte behalten 100 KiB; Zertifikatsuploads behalten ihre eigene 10-MiB-Grenze.

**Regression:** 110 sowie 1.000 Handler mit Umlauten, japanischem Text und Emoji bestehen GET/POST. Eingaben und kanonische Raw-/strukturierte GET-Darstellungen exakt an 2 MiB sind erneut speicherbar. Ein Byte bzw. mehrbyteiges Zeichen darüber und eine kompakte 3.000-Handler-Eingabe mit zu großer GET-Darstellung erhalten 413 ohne Teiländerung. Ein großer anderer API-Request bleibt auf 100 KiB begrenzt.

**Prüfung/Ergebnis:** `tests/config_integrity.test.cjs`; siehe Prüfprotokoll.

**Einschränkung:** Eine bereits vor dieser Reparatur extern erzeugte Datenbank mit mehr als 2 MiB expandierter Darstellung bleibt lesbar und unverändert, muss vor einer erneuten Speicherung verkleinert werden. Die Grenze begrenzt Dokumentgröße, nicht die garantierte Zahl beliebig großer Handlertexte.

## F12 – Vollständige Zertifikatsarchive

**Ursache/Funktion:** `serveCertificates()` sendete tar-stdout vor dem Exitstatus an HTTP. Ein späterer Fehler hinterließ ein unvollständiges Archiv mit 200.

**Korrektur:** Vollständige Archivierung vor Downloadbeginn in einem privaten temporären Verzeichnis (0700), Archiv/Manifest 0600. Vorprüfung auf reguläre Dateien und vollständige Zertifikat-/Schlüsselpaare. Ein explizites NUL-separiertes Dateimanifest verhindert, dass ein verschwundener Schlüssel still fehlt. Nur tar-Exitstatus 0 und eine nicht leere Ausgabedatei erlauben den Download; Fehler davor liefern 500. Client-Abbruch beendet den Kindprozess. Abschluss, Fehler und Abbruch bereinigen das temporäre Verzeichnis. Downloads verwenden `Cache-Control: no-store`.

Paarprüfung erfolgt in beiden Richtungen; verwaiste private Schlüssel werden ebenfalls abgewiesen. Die Identitäten und Dateitypen der erfassten Mitglieder werden nach tar erneut geprüft. Dadurch wird auch ein zwischen Vorprüfung und Archivierung gegen einen Symlink ausgetauschter Schlüssel vor HTTP 200 erkannt. Entsprechende Regressionen verwenden echtes tar.

**Regression:** `tests/certificate_archives.test.cjs` verwendet echtes tar, listet und extrahiert tatsächliche Archivmitglieder und prüft private Rechte, fehlende Schlüssel, Symlinks, einen deterministischen Lesefehler durch Entfernen eines bereits erfassten Schlüssels, Exitstatus/HTTP-Ergebnis sowie Client-Abbruch mit Prozess-/Dateibereinigung.

**Prüfung/Ergebnis:** Archivtests und bisherige Fehlersemantiktests im Backend; siehe Prüfprotokoll.

**Einschränkung:** Bei einem Verbindungsabbruch während der Übertragung kann HTTP keine vollständige Zustellung garantieren. Archivierungsfehler werden vor dem ersten erfolgreichen Downloadbyte erkannt. Spezialdateien und Symlinks im ACME-Speicher werden ausdrücklich abgewiesen.

## F13/F20 – Sessions und Logrotation

**Ursache/Funktionen:** Die Authentifizierung galt nur beim Öffnen von `/api/logs/stream`; `tail -f` folgte nach Rotation dem alten Inode.

**Korrektur:** `auth.js` verwaltet Stream-Abmeldungen pro Session. Logout beendet die eigenen Streams; Passwort-/MFA-Änderungen beenden alle widerrufenen Streams. Zusätzliche Datenbankprüfung vor jedem Chunk und alle 250 ms erkennt Ablauf und externen/globalen Widerruf. `tail -F` folgt dem Dateinamen nach Rotation. Gemeinsames Cleanup entfernt Reader, Timer und Listener; Readerfehler und Readerende beenden den Stream. Bisherige Fehlernachrichten für fehlende Logdatei und fehlenden Reader bleiben erhalten.

**Regression:** `tests/auth_security.test.cjs` öffnet echte HTTP-/SSE-Verbindungen und echte tail-Prozesse: Logout, Ablauf, Datenbankwiderruf, Passwort-/MFA-Änderung, isolierter Widerruf mehrerer Streams, Umbenennen/Neuerstellen, Readerende und wiederholtes Öffnen/Schließen mit Prozess-/Timerkontrolle. Auth-Unit-Tests prüfen außerdem Anmeldung/Abmeldung der Listener.

**Prüfung/Ergebnis:** Authentifizierungs-, SSE-, Backend- und Runtime-Tests; siehe Prüfprotokoll.

**Einschränkung:** Ein ruhender Stream erkennt externen Widerruf spätestens beim nächsten 250-ms-Intervall; vor jedem weiteren Datenchunk wird erneut geprüft. Rotationslatenz folgt dem Betriebssystemprogramm tail. Bereits vor Widerruf gesendete Netzwerkbytes lassen sich nicht zurückholen.

## F14 – Persistenter TOTP-Wiederverwendungsschutz

**Ursache/Funktionen:** `/login` und MFA-Aktivierung akzeptierten jeden aktuell gültigen Code erneut; der tatsächlich akzeptierte Zeitschritt wurde nicht gespeichert.

**Korrektur:** Migration um `users.totp_last_step`. Der tatsächlich von otplib akzeptierte Schritt wird pro aktuellem Benutzer/Secret gespeichert. Credential-Nachprüfung nach bcrypt, TOTP-Verbrauch und Session-Erzeugung erfolgen in einer unmittelbaren SQLite-Transaktion. Aktivierung konsumiert ebenfalls den Verifikationsschritt. Gleiches Secret in anderer Base32-Groß-/Kleinschreibung oder mit anderem zulässigen Padding setzt den Schutz nicht zurück; der Vergleich verwendet die kanonische Secret-Identität, die Verifikation prüft weiterhin die ursprüngliche Eingabe. Tatsächlicher Secret-Wechsel bzw. Deaktivierung beginnt eine neue Secret-Version. Bestehende Benutzer und Secrets bleiben erhalten. Die vorhandene Uhrtoleranz bleibt unverändert: nur der aktuelle 30-Sekunden-Schritt.

**Regression:** Kontrollierte Uhr in echten HTTP-Prozessen: erste Verwendung erfolgreich, direkte und parallele Verwendung (auch zwei Prozesse) nur einmal erfolgreich, späterer Schritt erfolgreich, echter Prozessneustart schützt weiter, vergangener/zukünftiger Schritt abgelehnt, späterer identischer sechsstelliger Zahlencode akzeptiert, Migration, Aktivierung/Secret-Wechsel/Schreibweise, Sessionrotation und Rollback bei fehlgeschlagener Session-Erzeugung.

**Prüfung/Ergebnis:** `tests/auth.test.cjs`, `tests/auth_security.test.cjs` und bestehende Backend-/Runtime-Authentifizierungstests; siehe Prüfprotokoll.

**Kompatibilität:** Nach Aktivierung oder Login muss für eine weitere Anmeldung der nächste Authenticator-Code verwendet werden. Gespeicherte Sessions und Secrets werden durch die Migration nicht gelöscht.

## Prüfprotokoll

Die Regressionen wurden gegen das fehlerhafte Verhalten ausgeführt und danach geprüft. Ein früher paralleler Gesamtlauf während laufender Implementierung war rot; die damaligen Fehler wurden im integrierten Lauf behoben, nicht als Erfolg gewertet.

Ein späterer paralleler Lauf bestand 194 Backend-/UI-Tests, hatte aber einen Caddy-Startfehler im bestehenden Test `proxy: HTTP source-port reuse cannot inherit NTLM authentication` (30/31). Der anschließende isolierte vollständige Proxy-Lauf bestand 31/31. Ein gezielter Konfigurationslauf hatte einmal `EADDRINUSE` im Test-Starthelfer; der nächste vollständige Lauf bestand. Die Testhelfer reservieren freie lokale Ports und geben sie vor dem Prozessstart frei; unter paralleler Last bleibt dieses Rennen möglich. Produktive Dienste wurden dafür nicht verwendet. Die endgültigen gemeinsamen Ergebnisse sind unten angegeben.

Verwendete Laufzeiten: Node 24.22.3 aus `/Users/stelios/.local/share/localcaddyhub-runtime/node-v24.22.3-darwin-arm64/bin`, Custom-Caddy `/Users/stelios/.local/share/localcaddyhub-runtime/caddy-2.11.9` mit lokalen Modulen, Coraza und Layer 4. Caddy erhält isolierte XDG-/Dateispeicher und lokale Ports. Es gab kein Merge, Deployment oder Push.

Tatsächlich ausgeführte integrierte Kommandos am 19.11.2026:

```sh
rtk proxy env PATH=/Users/stelios/.local/share/localcaddyhub-runtime/node-v24.22.3-darwin-arm64/bin:$PATH CADDY_BIN=/Users/stelios/.local/share/localcaddyhub-runtime/caddy-2.11.9 npm test
rtk proxy env PATH=/Users/stelios/.local/share/localcaddyhub-runtime/node-v24.22.3-darwin-arm64/bin:$PATH CADDY_BIN=/Users/stelios/.local/share/localcaddyhub-runtime/caddy-2.11.9 npm run test:proxy
rtk proxy env PATH=/Users/stelios/.local/share/localcaddyhub-runtime/node-v24.22.3-darwin-arm64/bin:$PATH CADDY_BIN=/Users/stelios/.local/share/localcaddyhub-runtime/caddy-2.11.9 npm run test:runtime
rtk git diff --check
```

| Prüfung | Ergebnis |
| --- | --- |
| `npm test` | 201 bestanden, 0 fehlgeschlagen, 0 übersprungen; enthält Backend, Auth/SSE, Archive, Revisions-/Größenprüfungen, echte Raw-Adaption, Runtime/Updater und beide Chromium-Flows |
| `npm run test:proxy` | 31 bestanden, 0 fehlgeschlagen, 0 übersprungen; tatsächlicher Custom-Caddy, Backend-Zähler, WAF, TLS/NTLM, Pfade, Reload und echte API-Validierung |
| `npm run test:runtime` | 3 bestanden, 0 fehlgeschlagen, 0 übersprungen |
| `git diff --check` | Exitstatus 0 |

Zusätzlich wurden während der Entwicklung die einzelnen Testdateien gezielt ausgeführt: Generator 29/29, Auth/SSE 31/31, Archiv-/Raw-Referenzprüfung 19/19, UI 19/19 und Konfigurationsintegrität einschließlich der nachträglichen Review-Regressionen. Die integrierten Läufe oben sind der gemeinsame Nachweis, dass die Reparaturen zusammen funktionieren.

**Unabhängiger Abschlussreview:** Der abschließende Ponytail-Reviewer prüfte den gesamten Umfang einschließlich angebundener unveränderter Funktionen. Alle bestätigten materiellen Befunde wurden durch Regressionstests verifiziert, korrigiert und erneut unabhängig geprüft. Der finale Review ist bestanden; keine materiellen Befunde bleiben offen. Der Reviewer führte zusätzlich die betroffenen Rollback-Regressionen selbst aus. Nach diesem Review wurde kein Produktcode mehr geändert.

**Blockierte Prüfungen:** Keine der angeforderten Backend-, Auth-, Runtime-, Browser- oder Custom-Caddy-Prüfungen ist blockiert. Nicht ausgeführt wurden produktive Migration/Traffic-Cutover oder Deployment; sie waren ausdrücklich nicht Teil der autorisierten Tests. Die unveränderten Go-Module wurden nicht erneut gebaut; die HTTP-Abnahme verwendet das vorhandene echte Custom-Caddy-Binary.
