<?php

/*
 +-----------------------------------------------------------------------+
 | Localization file of the Passkeys plugin                              |
 | Language: German (Germany)                                            |
 +-----------------------------------------------------------------------+
*/

$labels = [];
$labels['passkeys'] = 'Passkeys';
$labels['passkeysexplain'] = 'Mit Passkeys können Sie sich ohne Passwort anmelden – per Fingerabdruck, Gesichtserkennung, Gerätesperre oder Hardware-Sicherheitsschlüssel. Das Einrichten eines Passkeys ist optional und ändert Ihre gewohnte Anmeldung nicht.';
$labels['nopasskeys'] = 'Sie haben noch keine Passkeys hinzugefügt.';
$labels['addpasskey'] = 'Passkey hinzufügen';
$labels['removepasskey'] = 'Diesen Passkey entfernen';
$labels['renamepasskey'] = 'Diesen Passkey umbenennen';
$labels['passkeyname'] = 'Name';
$labels['passkeycreated'] = 'Hinzugefügt';
$labels['passkeylastused'] = 'Zuletzt verwendet';
$labels['passkeyneverused'] = 'Nie';
$labels['unnamedpasskey'] = 'Passkey';
$labels['passkeynameprompt'] = 'Name für diesen Passkey:';
$labels['loginwithpasskey'] = 'Mit Passkey anmelden';

$messages = [];
$messages['passkeyadded'] = 'Passkey erfolgreich hinzugefügt.';
$messages['passkeyadderror'] = 'Passkey konnte nicht hinzugefügt werden. Bitte erneut versuchen.';
$messages['passkeyaddcancelled'] = 'Die Passkey-Einrichtung wurde abgebrochen.';
$messages['passkeyremoved'] = 'Passkey erfolgreich entfernt.';
$messages['passkeyremoveerror'] = 'Passkey konnte nicht entfernt werden.';
$messages['passkeyrenameerror'] = 'Passkey konnte nicht umbenannt werden.';
$messages['passkeyremoveconfirm'] = 'Diesen Passkey entfernen? Sie können sich damit nicht mehr anmelden.';
$messages['notsupported'] = 'Ihr Browser unterstützt keine Passkeys.';
$messages['weberror'] = 'Der Passkey-Vorgang ist fehlgeschlagen. Bitte erneut versuchen.';
$messages['noprf'] = 'Dieses Gerät oder dieser Browser kann Ihr Passwort nicht sicher für die passwortlose Anmeldung speichern. Die Passkey-Anmeldung ist hier nicht verfügbar.';
$messages['libmissing'] = 'Die Passkey-Unterstützung ist auf dem Server nicht vollständig installiert. Bitte wenden Sie sich an Ihren Administrator.';
