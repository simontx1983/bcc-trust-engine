<?php
namespace BCCTrust\Security;

use Exception;
use Throwable;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Enterprise Transaction Manager
 *
 * - Ensures atomic DB operations
 * - Handles rollback on failure
 * - Safe for high concurrency
 * - Deadlock retry support
 */
class TransactionManager {

    /**
     * Execute callback inside DB transaction
     *
     * @param callable $callback
     * @param int $retryAttempts
     * @return mixed
     * @throws Exception
     */
    public static function run(callable $callback, int $retryAttempts = 3) {
        global $wpdb;

        $attempt = 0;
        $lastException = null;

        while ($attempt < $retryAttempts) {
            try {
                $attempt++;

                // Start transaction
                $wpdb->query('START TRANSACTION');

                // Execute callback
                $result = $callback();

                // Check if result indicates failure
                if ($result === false) {
                    throw new Exception('Transaction callback returned false');
                }

                // Commit if successful
                $wpdb->query('COMMIT');

                return $result;

            } catch (Throwable $e) { // Catch both Exception and Error
                // Rollback on error
                $wpdb->query('ROLLBACK');
                
                $lastException = $e;

                // Retry on deadlock (MySQL error 1213) or lock timeout (1205)
                if (self::isDeadlock($e) && $attempt < $retryAttempts) {
                    // Exponential backoff with jitter
                    $sleepMs = 100 * pow(2, $attempt - 1);
                    $jitter = mt_rand(0, (int)($sleepMs * 0.1));
                    usleep(($sleepMs + $jitter) * 1000);
                    
                    // Log retry attempt
                    if (defined('WP_DEBUG') && WP_DEBUG) {
                        error_log(sprintf(
                            '[BCC Trust Transaction] Deadlock detected, retrying (%d/%d) after %dms',
                            $attempt,
                            $retryAttempts,
                            $sleepMs + $jitter
                        ));
                    }
                    
                    continue;
                }

                // Re-throw if not a deadlock or out of retries
                throw $e;
            }
        }

        throw new Exception(
            'Transaction failed after ' . $retryAttempts . ' attempts',
            0,
            $lastException
        );
    }

    /**
     * Execute callback with read-only transaction
     */
    public static function read(callable $callback) {
        global $wpdb;

        $wpdb->query('START TRANSACTION');

        try {
            $result = $callback();
            $wpdb->query('COMMIT');
            return $result;
        } catch (Throwable $e) {
            $wpdb->query('ROLLBACK');
            throw $e;
        }
    }

    /**
     * Detect MySQL deadlock or lock timeout
     */
    private static function isDeadlock(Throwable $e): bool {
        $message = $e->getMessage();
        $code = $e->getCode();

        // Check error codes
        if (in_array($code, [1213, 1205, '1213', '1205', 40001])) { // 40001 is serialization failure
            return true;
        }

        // Check error messages
        $deadlockPatterns = [
            'Deadlock found',
            'deadlock',
            'Lock wait timeout',
            'try restarting transaction',
            '1213',
            '1205',
            '40001',
            'serialization failure'
        ];

        foreach ($deadlockPatterns as $pattern) {
            if (stripos($message, $pattern) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Execute with table lock (use sparingly)
     */
    public static function withLock(string $table, callable $callback) {
        global $wpdb;

        // Ensure table has prefix
        $fullTable = strpos($table, $wpdb->prefix) === 0 
            ? $table 
            : $wpdb->prefix . $table;

        // Verify table exists to prevent errors
        $tableExists = $wpdb->get_var("SHOW TABLES LIKE '{$fullTable}'") === $fullTable;
        if (!$tableExists) {
            throw new Exception("Table '{$fullTable}' does not exist");
        }

        $wpdb->query("LOCK TABLES {$fullTable} WRITE");

        try {
            $result = $callback();
            $wpdb->query('UNLOCK TABLES');
            return $result;
        } catch (Throwable $e) {
            $wpdb->query('UNLOCK TABLES');
            throw $e;
        }
    }

    /**
     * Execute with multiple table locks
     */
    public static function withLocks(array $tables, callable $callback) {
        global $wpdb;

        $lockClauses = [];
        foreach ($tables as $table => $type) {
            $fullTable = strpos($table, $wpdb->prefix) === 0 
                ? $table 
                : $wpdb->prefix . $table;
            
            // Verify table exists
            $tableExists = $wpdb->get_var("SHOW TABLES LIKE '{$fullTable}'") === $fullTable;
            if (!$tableExists) {
                throw new Exception("Table '{$fullTable}' does not exist");
            }
            
            $lockType = in_array(strtoupper($type), ['READ', 'WRITE']) 
                ? strtoupper($type) 
                : 'WRITE';
            
            $lockClauses[] = "{$fullTable} {$lockType}";
        }

        $wpdb->query("LOCK TABLES " . implode(', ', $lockClauses));

        try {
            $result = $callback();
            $wpdb->query('UNLOCK TABLES');
            return $result;
        } catch (Throwable $e) {
            $wpdb->query('UNLOCK TABLES');
            throw $e;
        }
    }

    /**
     * Execute with savepoint (nested transactions)
     */
    public static function savepoint(string $name, callable $callback) {
        global $wpdb;

        // Sanitize savepoint name to prevent SQL injection
        $name = preg_replace('/[^a-zA-Z0-9_]/', '', $name);
        
        $wpdb->query("SAVEPOINT {$name}");

        try {
            $result = $callback();
            return $result;
        } catch (Throwable $e) {
            $wpdb->query("ROLLBACK TO SAVEPOINT {$name}");
            throw $e;
        }
    }

    /**
     * Check if in transaction
     */
    public static function inTransaction(): bool {
        global $wpdb;
        
        // MySQL 5.6+ has @@in_transaction
        $inTransaction = $wpdb->get_var("SELECT @@in_transaction");
        
        return (bool) $inTransaction;
    }

    /**
     * Get transaction isolation level
     */
    public static function getIsolationLevel(): string {
        global $wpdb;
        
        $level = $wpdb->get_var("SELECT @@transaction_isolation");
        
        return $level ?: 'REPEATABLE-READ';
    }

    /**
     * Set transaction isolation level for current session
     */
    public static function setIsolationLevel(string $level): bool {
        global $wpdb;
        
        $validLevels = [
            'READ UNCOMMITTED',
            'READ COMMITTED',
            'REPEATABLE READ',
            'SERIALIZABLE'
        ];
        
        if (!in_array(strtoupper($level), $validLevels)) {
            return false;
        }
        
        $wpdb->query("SET SESSION TRANSACTION ISOLATION LEVEL {$level}");
        
        return true;
    }
}