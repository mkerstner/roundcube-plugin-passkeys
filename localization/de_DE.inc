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
$labels['passkeypassword'] = 'Aktuelles Passwort';
$labels['passkeyaddhint'] = 'Geben Sie dem Passkey einen Namen und bestätigen Sie mit Ihrem aktuellen Passwort. Das Passwort wird verschlüsselt gespeichert; nur dieser Passkey kann es entschlüsseln.';
$labels['updatepasskey'] = 'Passkey aktualisieren';
$labels['passkeyupdatehint'] = 'Ihr Passwort hat sich geändert, seit dieser Passkey eingerichtet wurde. Bestätigen Sie mit Ihrem aktuellen Passwort und anschließend mit dem Passkey.';
$labels['passkeyneedsupdate'] = 'muss aktualisiert werden';
$labels['loginwithpasskey'] = 'Mit Passkey anmelden';
$labels['orsigninwithpasskey'] = 'oder mit Passkey anmelden';

$messages = [];
$messages['passkeyadded'] = 'Passkey erfolgreich hinzugefügt.';
$messages['passkeyadderror'] = 'Passkey konnte nicht hinzugefügt werden. Bitte erneut versuchen.';
$messages['passkeycancelled'] = 'Der Passkey-Vorgang wurde abgebrochen.';
$messages['passwordincorrect'] = 'Das Passwort ist falsch.';
$messages['passkeystale'] = 'Ihr Passwort hat sich geändert, seit dieser Passkey eingerichtet wurde, daher kann er Sie nicht mehr anmelden. Melden Sie sich mit Ihrem Passwort an; danach können Sie den Passkey aktualisieren.';
$messages['passkeystaleprompt'] = 'Ihr Passwort hat sich geändert, seit Sie Ihre Passkeys eingerichtet haben. Aktualisieren Sie sie, um sich weiterhin ohne Passwort anzumelden.';
$messages['passkeyupdated'] = 'Passkey aktualisiert.';
$messages['passkeyupdateerror'] = 'Passkey konnte nicht aktualisiert werden.';
$messages['passkeyremoved'] = 'Passkey erfolgreich entfernt.';
$messages['passkeyremoveerror'] = 'Passkey konnte nicht entfernt werden.';
$messages['passkeyrenameerror'] = 'Passkey konnte nicht umbenannt werden.';
$messages['passkeyremoveconfirm'] = 'Diesen Passkey entfernen? Sie können sich damit nicht mehr anmelden.';
$messages['notsupported'] = 'Ihr Browser unterstützt keine Passkeys.';
$messages['weberror'] = 'Der Passkey-Vorgang ist fehlgeschlagen. Bitte erneut versuchen.';
$messages['noprf'] = 'Dieses Gerät oder dieser Browser kann Ihr Passwort nicht sicher für die passwortlose Anmeldung speichern. Die Passkey-Anmeldung ist hier nicht verfügbar.';
$messages['libmissing'] = 'Die Passkey-Unterstützung ist auf dem Server nicht vollständig installiert. Bitte wenden Sie sich an Ihren Administrator.';
