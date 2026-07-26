<?php

/*
 +-----------------------------------------------------------------------+
 | Localization file of the Passkeys plugin                              |
 | Language: English (US)                                                |
 +-----------------------------------------------------------------------+
*/

$labels = [];
$labels['passkeys'] = 'Passkeys';
$labels['passkeysexplain'] = 'Passkeys let you sign in without a password using your device\'s fingerprint, face, screen lock, or a hardware security key. Enrolling a passkey is optional and does not change your usual sign-in.';
$labels['nopasskeys'] = 'You have not added any passkeys yet.';
$labels['addpasskey'] = 'Add a passkey';
$labels['removepasskey'] = 'Remove this passkey';
$labels['renamepasskey'] = 'Rename this passkey';
$labels['passkeyname'] = 'Name';
$labels['passkeycreated'] = 'Added';
$labels['passkeylastused'] = 'Last used';
$labels['passkeyneverused'] = 'Never';
$labels['unnamedpasskey'] = 'Passkey';
$labels['passkeynameprompt'] = 'Name for this passkey:';
$labels['loginwithpasskey'] = 'Sign in with a passkey';

$messages = [];
$messages['passkeyadded'] = 'Passkey added successfully.';
$messages['passkeyadderror'] = 'Could not add the passkey. Please try again.';
$messages['passkeyaddcancelled'] = 'Passkey setup was cancelled.';
$messages['passkeyremoved'] = 'Passkey removed successfully.';
$messages['passkeyremoveerror'] = 'Could not remove the passkey.';
$messages['passkeyrenameerror'] = 'Could not rename the passkey.';
$messages['passkeyremoveconfirm'] = 'Remove this passkey? You will no longer be able to sign in with it.';
$messages['notsupported'] = 'Your browser does not support passkeys.';
$messages['weberror'] = 'The passkey operation failed. Please try again.';
$messages['noprf'] = 'This device or browser cannot store your password securely for passwordless sign-in. Passkey sign-in is not available here.';
$messages['libmissing'] = 'Passkey support is not fully installed on the server. Please contact your administrator.';
