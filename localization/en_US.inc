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
$labels['passkeypassword'] = 'Current password';
$labels['passkeyaddhint'] = 'Give the passkey a name and confirm with your current password. The password is stored encrypted with a key only this passkey can unlock.';
$labels['updatepasskey'] = 'Update passkey';
$labels['passkeyupdatehint'] = 'Your password has changed since this passkey was set up. Confirm with your current password, then with the passkey.';
$labels['passkeyneedsupdate'] = 'needs update';
$labels['loginwithpasskey'] = 'Sign in with a passkey';
$labels['orsigninwithpasskey'] = 'or sign in using passkeys';

$messages = [];
$messages['passkeyadded'] = 'Passkey added successfully.';
$messages['passkeyadderror'] = 'Could not add the passkey. Please try again.';
$messages['passkeycancelled'] = 'The passkey request was cancelled.';
$messages['passwordincorrect'] = 'The password is incorrect.';
$messages['passkeystale'] = 'Your password has changed since this passkey was set up, so it can no longer sign you in. Sign in with your password; you can then update the passkey.';
$messages['passkeystaleprompt'] = 'Your password has changed since you set up your passkeys. Update them to keep signing in without a password.';
$messages['passkeyupdated'] = 'Passkey updated.';
$messages['passkeyupdateerror'] = 'Could not update the passkey.';
$messages['passkeyremoved'] = 'Passkey removed successfully.';
$messages['passkeyremoveerror'] = 'Could not remove the passkey.';
$messages['passkeyrenameerror'] = 'Could not rename the passkey.';
$messages['passkeyremoveconfirm'] = 'Remove this passkey? You will no longer be able to sign in with it.';
$messages['notsupported'] = 'Your browser does not support passkeys.';
$messages['weberror'] = 'The passkey operation failed. Please try again.';
$messages['noprf'] = 'This device or browser cannot store your password securely for passwordless sign-in. Passkey sign-in is not available here.';
$messages['libmissing'] = 'Passkey support is not fully installed on the server. Please contact your administrator.';
