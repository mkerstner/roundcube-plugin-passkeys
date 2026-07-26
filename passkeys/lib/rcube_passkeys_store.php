<?php

/*
 +-----------------------------------------------------------------------+
 | Passkeys plugin for Roundcube                                         |
 |                                                                       |
 | Persistence layer for enrolled WebAuthn/FIDO2 credentials.            |
 |                                                                       |
 | Licensed under the GNU General Public License version 3 or           |
 | any later version with exceptions for skins & plugins.               |
 +-----------------------------------------------------------------------+
*/

/**
 * Data-access object for the `passkeys_credentials` table.
 *
 * All binary WebAuthn values (credential id, wrapped secret, IV) are stored
 * base64/base64url-encoded as text so the schema stays portable across the
 * MySQL, PostgreSQL and SQLite backends Roundcube supports.
 */
class rcube_passkeys_store
{
    /** @var rcube_db */
    private $db;

    /** @var string */
    private $table;

    public function __construct(rcube_db $db)
    {
        $this->db = $db;
        $this->table = $db->table_name('passkeys_credentials', true);
    }

    /**
     * Return all credentials enrolled by the given user, newest first.
     *
     * @param int $user_id
     *
     * @return array<int, array<string, mixed>>
     */
    public function list_by_user($user_id)
    {
        $result = $this->db->query(
            "SELECT * FROM {$this->table} WHERE `user_id` = ? ORDER BY `created` DESC",
            (int) $user_id
        );

        $rows = [];
        while ($row = $this->db->fetch_assoc($result)) {
            $rows[] = $row;
        }

        return $rows;
    }

    /**
     * Number of credentials enrolled by the given user.
     *
     * @param int $user_id
     *
     * @return int
     */
    public function count_by_user($user_id)
    {
        return count($this->list_by_user($user_id));
    }

    /**
     * Fetch a single credential owned by the given user.
     *
     * @param int    $user_id
     * @param string $credential_id base64url credential id
     *
     * @return array<string, mixed>|null
     */
    public function get($user_id, $credential_id)
    {
        $result = $this->db->query(
            "SELECT * FROM {$this->table} WHERE `user_id` = ? AND `credential_id` = ?",
            (int) $user_id,
            (string) $credential_id
        );

        $row = $this->db->fetch_assoc($result);

        return $row ?: null;
    }

    /**
     * Look up a credential by its id alone (used on the login path, where the
     * user is not yet known but the authenticator returned a user handle).
     *
     * @param string $credential_id base64url credential id
     *
     * @return array<string, mixed>|null
     */
    public function get_by_credential_id($credential_id)
    {
        $result = $this->db->query(
            "SELECT * FROM {$this->table} WHERE `credential_id` = ?",
            (string) $credential_id
        );

        $row = $this->db->fetch_assoc($result);

        return $row ?: null;
    }

    /**
     * Insert a freshly enrolled credential.
     *
     * @param array<string, mixed> $data
     *
     * @return bool
     */
    public function insert(array $data)
    {
        $now = date('Y-m-d H:i:s');

        $result = $this->db->query(
            "INSERT INTO {$this->table}"
                . " (`credential_id`, `user_id`, `public_key`, `sign_count`, `aaguid`,"
                . " `label`, `transports`, `prf_supported`, `wrapped_secret`, `wrap_iv`, `created`)"
                . " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (string) $data['credential_id'],
            (int) $data['user_id'],
            (string) $data['public_key'],
            (int) ($data['sign_count'] ?? 0),
            $data['aaguid'] ?? null,
            $data['label'] ?? null,
            $data['transports'] ?? null,
            !empty($data['prf_supported']) ? 1 : 0,
            $data['wrapped_secret'] ?? null,
            $data['wrap_iv'] ?? null,
            $now
        );

        return $this->db->affected_rows($result) > 0;
    }

    /**
     * Update the signature counter after a successful assertion and stamp
     * the last-used time.
     *
     * @param string $credential_id
     * @param int    $sign_count
     *
     * @return bool
     */
    public function update_sign_count($credential_id, $sign_count)
    {
        $result = $this->db->query(
            "UPDATE {$this->table} SET `sign_count` = ?, `last_used` = ? WHERE `credential_id` = ?",
            (int) $sign_count,
            date('Y-m-d H:i:s'),
            (string) $credential_id
        );

        return $this->db->affected_rows($result) > 0;
    }

    /**
     * Rename a credential's user-visible label.
     *
     * @param int    $user_id
     * @param string $credential_id
     * @param string $label
     *
     * @return bool
     */
    public function rename($user_id, $credential_id, $label)
    {
        $result = $this->db->query(
            "UPDATE {$this->table} SET `label` = ? WHERE `user_id` = ? AND `credential_id` = ?",
            (string) $label,
            (int) $user_id,
            (string) $credential_id
        );

        return $this->db->affected_rows($result) > 0;
    }

    /**
     * Delete a credential owned by the given user.
     *
     * @param int    $user_id
     * @param string $credential_id
     *
     * @return bool
     */
    public function remove($user_id, $credential_id)
    {
        $result = $this->db->query(
            "DELETE FROM {$this->table} WHERE `user_id` = ? AND `credential_id` = ?",
            (int) $user_id,
            (string) $credential_id
        );

        return $this->db->affected_rows($result) > 0;
    }

    /**
     * Delete every credential owned by the given user.
     *
     * @param int $user_id
     *
     * @return bool
     */
    public function remove_all($user_id)
    {
        $result = $this->db->query(
            "DELETE FROM {$this->table} WHERE `user_id` = ?",
            (int) $user_id
        );

        return $this->db->affected_rows($result) > 0;
    }
}
