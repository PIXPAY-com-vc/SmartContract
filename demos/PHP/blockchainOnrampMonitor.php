<?php
declare(strict_types=1);
require_once __DIR__ . '/vendor/autoload.php';
require_once __DIR__ . '/HDWalletSDK.php';

use Web3\Web3;
use Web3\Contract;
use Web3\Providers\HttpProvider;
use Web3\RequestManagers\HttpRequestManager;
use Web3p\EthereumTx\Transaction;
use function kornrunner\keccak\keccak{};

// ==================================================
// Execution Instructions
// ==================================================
/*
/***********************************************************************************************************************
 To run the complete system:

# Terminal 1 - Event Listener
php monitor.php listenEvents

# Terminal 2 - Queue Processor
php monitor.php processQueue

# Terminal 3 - Gas Verifier
php monitor.php verifyGas

# View all logs
tail -f logs/$(date +%Y-%m-%d).log

# Filter log types
tail -f logs/$(date +%Y-%m-%d).log | grep 'ERROR'
tail -f logs/$(date +%Y-%m-%d).log | grep 'METRICS'

For production environment setup:

/* On Linux systems: Create systemd services for each worker:

# /etc/systemd/system/monitor-processQueue.service
[Unit]
Description=Blockchain Transaction Processor

[Service]
ExecStart=/usr/bin/php /path/monitor.php processQueue
Restart=always
EnvironmentFile=/etc/default/monitor

[Install]
WantedBy=multi-user.target

# /etc/systemd/system/monitor-verifyGas.service
[Unit]
Description=Gas Confirmation Verifier

[Service]
ExecStart=/usr/bin/php /path/monitor.php verifyGas
Restart=always
EnvironmentFile=/etc/default/monitor

[Install]
WantedBy=multi-user.target

# /etc/systemd/system/monitor-listenEvents.service
[Unit]
Description=Blockchain Event Listener
After=network.target

[Service]
ExecStart=/usr/bin/php /full/path/monitor.php listenEvents
Restart=always
RestartSec=5
User=www-data
Group=www-data
Environment="APP_ENV=production"
WorkingDirectory=/full/path
EnvironmentFile=/etc/default/monitor
# Security configuration
ProtectSystem=full
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target

Service management:

# Reload configurations
sudo systemctl daemon-reload

# Start all services
sudo systemctl start monitor-listenEvents monitor-processQueue monitor-verifyGas

# Enable auto-start
sudo systemctl enable monitor-listenEvents monitor-processQueue monitor-verifyGas

# Check status
systemctl status monitor-listenEvents monitor-processQueue monitor-verifyGas

# Stop all services
sudo systemctl stop monitor-listenEvents monitor-processQueue monitor-verifyGas

Permissions:

sudo chmod 640 /etc/systemd/system/monitor-*.service
sudo chown root:root /etc/systemd/system/monitor-*.service

Environment variables:

# Create environment file
sudo nano /etc/default/monitor

# Content:
APP_ENV=production
HOT_WALLET_PRIVATE_KEY=your_private_key
DB_PASSWORD=your_db_password

Monitoring:

# View real-time logs
journalctl -u monitor-listenEvents -f

# Memory statistics
journalctl -u monitor-verifyGas --since "1 hour ago" | grep memory_usage

# Daily health check
sudo nano /etc/cron.daily/monitor-check

#!/bin/bash
systemctl is-active -q monitor-listenEvents || systemctl restart monitor-listenEvents
systemctl is-active -q monitor-processQueue || systemctl restart monitor-processQueue
systemctl is-active -q monitor-verifyGas || systemctl restart monitor-verifyGas

Important: Replace:
    /full/path/ with your project's actual directory
    /usr/bin/php with full path to your PHP (which php)
    Adjust User and Group according to your server configuration
**********************************************************************************************************************/

// ==================================================
// Main Configuration
// ==================================================
$config = [
    'httpRPC' => "https://polygon-rpc.com",
    'monitorContractAddress' => "0x...", // Monitor contract address
    'hotWalletAddress' => "0x...", // Hot wallet address
    'hotWalletPrivateKey' => getenv('HOT_WALLET_PRIVATE_KEY'), // From environment variables
    'blockConfirmations' => 2, // Required block confirmations
    'gasAmount' => "0.06", // MATIC amount for gas fees
    'maxRetries' => 3, // Maximum retry attempts
    'retryDelay' => 5, // Seconds between retries
    'maxConcurrentTasks' => 10, // Parallel processing limit
    'pollingInterval' => 10, // Polling interval in seconds
    'dbConnection' => [
        'host' => getenv('DB_HOST') ?: 'localhost',
        'dbname' => getenv('DB_NAME') ?: 'blockchain_monitor',
        'user' => getenv('DB_USER') ?: 'root',
        'password' => getenv('DB_PASSWORD') ?: '',
    ],
    'tokens' => [
        'USDT' => [
            'address' => '0xc2132D05D31c914a87C6611C10748AEb04B58e8F',
            'decimals' => 6
        ],
        'VRL' => [
            'address' => '0x6fb1d4a09436c86B4F8B2603A37cbB6432743D66',
            'decimals' => 2
        ]
    ],
    'logPath' => __DIR__ . '/logs/',
    'queuePath' => __DIR__ . '/queue/',
    'workers' => [
        'processQueue' => [
            'enabled' => true,
            'max_memory' => '512M'
        ],
        'verifyGas' => [
            'enabled' => true,
            'max_memory' => '256M'
        ]
    ],
    'gasCheckInterval' => 5, 
];

// Initialize directories
foreach ([$config['logPath'], $config['queuePath']] as $dir) {
    if (!is_dir($dir)) {
        mkdir($dir, 0755, true);
    }
}

// Validate command line arguments
if ($argc < 2) {
    die("Usage: php monitor.php <command>\nAvailable commands: processQueue, verifyGas, listenEvents\n");
}

// ==================================================
// Blockchain Connection Setup
// ==================================================
$web3 = new Web3(new HttpProvider(new HttpRequestManager($config['httpRPC'])));
$monitorABI = file_get_contents(__DIR__ . '/monitor.json');
$contract = new Contract($web3->provider, json_decode($monitorABI, true));
$hdWallet = new HDWalletSDK();

// ==================================================
// Database Connection
// ==================================================
$pdo = new PDO(
    "mysql:host={$config['dbConnection']['host']};dbname={$config['dbConnection']['dbname']}",
    $config['dbConnection']['user'],
    $config['dbConnection']['password'],
    [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
);

// ==================================================
// Database Schema Setup
// ==================================================
setupDatabase($pdo);

function setupDatabase(PDO $pdo): void {
    // Pending transactions table
    $pdo->exec("CREATE TABLE IF NOT EXISTS pending_transactions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        from_address VARCHAR(42) NOT NULL,
        to_address VARCHAR(42) NOT NULL,
        amount VARCHAR(50) NOT NULL,
        token VARCHAR(10) NOT NULL,
        tx_hash VARCHAR(66) NULL,
        status ENUM('pending_gas','processing_gas','gas_failed','pending_token','processing_token','completed','failed') NOT NULL DEFAULT 'pending_gas',
        retry_count INT NOT NULL DEFAULT 0,
        next_retry DATETIME NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        error_message TEXT NULL,
        raw_event TEXT NULL,
        INDEX (status),
        INDEX (next_retry)
    )");

    // Processed events table
    $pdo->exec("CREATE TABLE IF NOT EXISTS processed_events (
        id INT AUTO_INCREMENT PRIMARY KEY,
        tx_hash VARCHAR(66) NOT NULL,
        block_number INT NOT NULL,
        event_name VARCHAR(50) NOT NULL,
        processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY (tx_hash, event_name)
    )");
    
    // System state table
    $pdo->exec("CREATE TABLE IF NOT EXISTS monitor_state (
        id INT AUTO_INCREMENT PRIMARY KEY,
        key_name VARCHAR(50) NOT NULL,
        value TEXT NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE KEY (key_name)
    )");
}

// ==================================================
// Logging System
// ==================================================
function logger(string $level, string $message, array $context = []): void {
    global $config;
    
    $logEntry = [
        'timestamp' => date('Y-m-d H:i:s'),
        'level' => $level,
        'message' => $message,
        'context' => $context
    ];
    
    file_put_contents(
        $config['logPath'] . date('Y-m-d') . '.log',
        json_encode($logEntry) . PHP_EOL,
        FILE_APPEND
    );
    
    if (getenv('APP_ENV') !== 'production') {
        echo "[{$logEntry['timestamp']}] [{$level}] {$message}" . PHP_EOL;
    }
}

// ==================================================
// Block Management
// ==================================================
function getLastProcessedBlock(PDO $pdo): int {
    $stmt = $pdo->prepare("SELECT value FROM monitor_state WHERE key_name = 'last_processed_block'");
    $stmt->execute();
    return $stmt->fetchColumn() ?: 0;
}

function updateLastProcessedBlock(PDO $pdo, int $blockNumber): void {
    $stmt = $pdo->prepare("UPDATE monitor_state SET value = ? WHERE key_name = 'last_processed_block'");
    $stmt->execute([$blockNumber]);
}

function getCurrentBlockNumber(): int {
    global $web3;
    try {
        $block = $web3->eth->blockNumber();
        return hexdec($block->toString());
    } catch (Exception $e) {
        logger('error', 'Failed to fetch block number', ['error' => $e->getMessage()]);
        return 0;
    }
}

// ==================================================
// Event Processing
// ==================================================
function isEventProcessed(PDO $pdo, string $txHash, string $eventName): bool {
    $stmt = $pdo->prepare("SELECT id FROM processed_events WHERE tx_hash = ? AND event_name = ?");
    $stmt->execute([$txHash, $eventName]);
    return (bool)$stmt->fetch();
}

function markEventAsProcessed(PDO $pdo, string $txHash, int $blockNumber, string $eventName): void {
    $stmt = $pdo->prepare("INSERT IGNORE INTO processed_events (tx_hash, block_number, event_name) VALUES (?,?,?)");
    $stmt->execute([$txHash, $blockNumber, $eventName]);
}

// ==================================================
// User Management
// ==================================================
function getUserIdByWalletAddress(PDO $pdo, string $walletAddress): ?int {
    try {
        $stmt = $pdo->prepare("SELECT user_id FROM user_wallets WHERE wallet_address = ?");
        $stmt->execute([strtolower($walletAddress)]);
        return $stmt->fetchColumn() ?: null;
    } catch (PDOException $e) {
        logger('error', 'Database query failed', ['error' => $e->getMessage()]);
        return null;
    }
}

// ==================================================
// ABI Decoding Functions
// ==================================================
function decodeEventData(array $contractAbi, array $log): array {
    $eventAbi = null;
    foreach ($contractAbi as $item) {
        if (isset($item['type'], $item['name']) && 
            $item['type'] === 'event' && 
            $item['name'] === 'Deposit') {
            $eventAbi = $item;
            break;
        }
    }

    if (!$eventAbi) {
        throw new RuntimeException("Deposit event not found in ABI");
    }

    $decoded = [];
    $indexedParams = [];
    $nonIndexedParams = [];

    foreach ($eventAbi['inputs'] as $input) {
        ($input['indexed'] ?? false) ? $indexedParams[] = $input : $nonIndexedParams[] = $input;
    }

    foreach ($indexedParams as $index => $param) {
        $topicIndex = $index + 1;
        if (isset($log['topics'][$topicIndex])) {
            $topic = $log['topics'][$topicIndex];
            switch ($param['type']) {
                case 'address':
                    $decoded[$param['name']] = '0x' . substr($topic, 26);
                    break;
                case 'uint256':
                    $decoded[$param['name']] = hexdec(substr($topic, 2));
                    break;
                default:
                    $decoded[$param['name']] = $topic;
            }
        }
    }

    if (isset($log['data']) && $log['data'] !== '0x') {
        $data = substr($log['data'], 2);
        $position = 0;
        
        foreach ($nonIndexedParams as $param) {
            list($value, $newPos) = decodeParam($param['type'], $data, $position);
            $decoded[$param['name']] = $value;
            $position = $newPos;
        }
    }

    return $decoded;
}

function decodeParam(string $type, string &$data, int $pos): array {
    $staticTypes = [
        'address' => 32, 
        'bool' => 32,
        'uint256' => 32,
        'int256' => 32
    ];

    if (isset($staticTypes[$type])) {
        $bytes = substr($data, $pos * 2, $staticTypes[$type] * 2);
        $pos += $staticTypes[$type];

        switch ($type) {
            case 'address':
                return ['0x' . substr($bytes, -40), $pos];
            case 'bool':
                return [hexdec($bytes) !== 0, $pos];
            case 'uint256':
                return [hexdec($bytes), $pos];
            default:
                return ['0x' . $bytes, $pos];
        }
    }

    if ($type === 'string' || $type === 'bytes') {
        $offsetBytes = hexdec(substr($data, $pos * 2, 64));
        $offset = $offsetBytes * 2;
        $pos += 32;

        $lengthBytes = hexdec(substr($data, $offset, 64));
        $length = $lengthBytes * 2;
        $valueData = substr($data, $offset + 64, $length);

        if ($type === 'string') {
            return [hex2bin($valueData), $pos];
        }

        $decoded = hex2bin($valueData);
        if (function_exists('json_validate') && json_validate($decoded)) { 
            return [json_decode($decoded, true), $pos];
        }
        return [$decoded, $pos];
    }

    throw new RuntimeException("Unsupported type: $type");
}

// ==================================================
// MATIC Transaction Handling
// ==================================================
function sendMATIC(string $toAddress, string $amount, string $privateKey, callable $callback): void {
    global $web3, $hdWallet;

    $fromAddress = $hdWallet->getAddressFromPrivateKey($privateKey);

    $web3->eth->getTransactionCount($fromAddress, 'pending', function ($err, $nonceResult) use ($callback, $fromAddress, $toAddress, $amount, $privateKey) {
        if ($err) {
            logger('error', 'Failed to get nonce', ['error' => $err->getMessage()]);
            $callback(["status" => 0, "error" => $err->getMessage()]);
            return;
        }

        $nonce = hexdec($nonceResult->toString());

        $web3->eth->gasPrice(function ($err, $gasPriceResult) use ($nonce, $callback, $fromAddress, $toAddress, $amount, $privateKey) {
            if ($err) {
                logger('error', 'Failed to get gas price', ['error' => $err->getMessage()]);
                $callback(["status" => 0, "error" => $err->getMessage()]);
                return;
            }

            $gasPrice = hexdec($gasPriceResult->toString());
            $gasPriceIncreased = (int)($gasPrice * 1.2);
            $valueInWei = bcmul($amount, "1000000000000000000");

            $transaction = new Transaction([
                'nonce' => '0x' . dechex($nonce),
                'gasPrice' => '0x' . dechex($gasPriceIncreased),
                'gas' => '0x5208',
                'to' => $toAddress,
                'value' => '0x' . dechex((int)$valueInWei),
                'chainId' => 137
            ]);

            try {
                $signedTx = $transaction->sign($privateKey);
                $web3->eth->sendRawTransaction('0x' . $signedTx, function ($err, $txResult) use ($callback, $fromAddress, $toAddress, $amount) {
                    if ($err) {
                        logger('error', 'MATIC send failed', [
                            'error' => $err->getMessage(),
                            'to' => $toAddress,
                            'amount' => $amount
                        ]);
                        $callback(["status" => 0, "error" => $err->getMessage()]);
                        return;
                    }
                    
                    $txHash = $txResult->toString();
                    logger('info', 'MATIC sent successfully', [
                        'from' => $fromAddress,
                        'to' => $toAddress,
                        'amount' => $amount,
                        'txHash' => $txHash
                    ]);
                    $callback(["status" => 1, "hash" => $txHash]);
                });
            } catch (Throwable $e) {
                logger('error', 'Transaction signing failed', ['error' => $e->getMessage()]);
                $callback(["status" => 0, "error" => $e->getMessage()]);
            }
        });
    });
}

// ==================================================
// Token Transaction Handling (USDT/VRL)
// ==================================================
function sendToken(string $toAddress, string $amount, string $privateKey, string $tokenSymbol, callable $callback): void {
    global $web3, $hdWallet, $config;

    try {
        if (!isset($config['tokens'][$tokenSymbol])) {
            throw new RuntimeException("Token not configured: $tokenSymbol");
        }

        $tokenConfig = $config['tokens'][$tokenSymbol];
        $tokenAddress = $tokenConfig['address'];
        $decimals = $tokenConfig['decimals'];

        $tokenAbi = json_decode('[{"constant":false,"inputs":[{"name":"_to","type":"address"},{"name":"_value","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"type":"function"}]', true);

        $tokenContract = new Contract($web3->provider, $tokenAbi);
        $fromAddress = $hdWallet->getAddressFromPrivateKey($privateKey);

        $web3->eth->getTransactionCount($fromAddress, 'pending', function ($err, $nonceResult) use ($callback, $fromAddress, $toAddress, $amount, $privateKey, $tokenAddress, $decimals, $tokenContract, $tokenSymbol) {
            if ($err) {
                logger('error', 'Failed to get nonce', ['error' => $err->getMessage()]);
                $callback(["status" => 0, "error" => $err->getMessage()]);
                return;
            }

            $nonce = hexdec($nonceResult->toString());

            $web3->eth->gasPrice(function ($err, $gasPriceResult) use ($nonce, $callback, $fromAddress, $toAddress, $amount, $privateKey, $tokenAddress, $decimals, $tokenContract, $tokenSymbol) {
                if ($err) {
                    logger('error', 'Failed to get gas price', ['error' => $err->getMessage()]);
                    $callback(["status" => 0, "error" => $err->getMessage()]);
                    return;
                }

                $gasPrice = hexdec($gasPriceResult->toString());
                $gasPriceIncreased = (int)($gasPrice * 1.2);
                $valueInSmallestUnit = bcmul($amount, bcpow("10", $decimals));

                $data = $tokenContract->encodeFunctionCall('transfer', [
                    $toAddress,
                    $valueInSmallestUnit
                ]);

                $transaction = new Transaction([
                    'nonce' => '0x' . dechex($nonce),
                    'gasPrice' => '0x' . dechex($gasPriceIncreased),
                    'gas' => '0x' . dechex(100000),
                    'to' => $tokenAddress,
                    'value' => '0x0',
                    'data' => $data,
                    'chainId' => 137
                ]);

                try {
                    $signedTx = $transaction->sign($privateKey);
                    $web3->eth->sendRawTransaction('0x' . $signedTx, function ($err, $txResult) use ($callback, $fromAddress, $toAddress, $amount, $tokenSymbol) {
                        if ($err) {
                            logger('error', "Failed to send $tokenSymbol", [
                                'error' => $err->getMessage(),
                                'to' => $toAddress,
                                'amount' => $amount
                            ]);
                            $callback(["status" => 0, "error" => $err->getMessage()]);
                            return;
                        }

                        $txHash = $txResult->toString();
                        logger('info', "$tokenSymbol sent successfully", [
                            'from' => $fromAddress,
                            'to' => $toAddress,
                            'amount' => $amount,
                            'txHash' => $txHash
                        ]);
                        $callback(["status" => 1, "hash" => $txHash]);
                    });
                } catch (Throwable $e) {
                    logger('error', 'Token transaction failed', ['error' => $e->getMessage()]);
                    $callback(["status" => 0, "error" => $e->getMessage()]);
                }
            });
        });
    } catch (Throwable $e) {
        logger('error', "Token send error: $tokenSymbol", ['error' => $e->getMessage()]);
        $callback(["status" => 0, "error" => $e->getMessage()]);
    }
}

// ==================================================
// Transaction Status Checking
// ==================================================
function checkTransactionStatus(string $txHash, callable $callback): void {
    global $web3;
    
    $web3->eth->getTransactionReceipt($txHash, function ($err, $receipt) use ($callback) {
        if ($err) {
            $callback(null);
            return;
        }
        
        $status = $receipt !== null ? (isset($receipt->status) ? hexdec($receipt->status) : 1) : null;
        $callback($status);
    });
}

// ==================================================
// Queue Management
// ==================================================
function queueTransaction(PDO $pdo, int $userId, string $fromAddress, string $toAddress, string $amount, string $token, array $rawEvent): int {
    $stmt = $pdo->prepare("INSERT INTO pending_transactions 
        (user_id, from_address, to_address, amount, token, status, raw_event) 
        VALUES (?, ?, ?, ?, ?, 'pending_gas', ?)");
    
    $stmt->execute([
        $userId,
        $fromAddress,
        $toAddress,
        $amount,
        $token,
        json_encode($rawEvent)
    ]);
    
    return $pdo->lastInsertId();
}

function updateTransactionStatus(PDO $pdo, int $txId, string $status, ?string $txHash = null, ?string $errorMessage = null): void {
    $sql = "UPDATE pending_transactions SET status = ?";
    $params = [$status];

    if ($txHash !== null) {
        $sql .= ", tx_hash = ?";
        $params[] = $txHash;
    }

    if ($errorMessage !== null) {
        $sql .= ", error_message = ?";
        $params[] = $errorMessage;
    }

    if ($status === 'failed') {
        $sql .= ", retry_count = retry_count + 1, next_retry = DATE_ADD(NOW(), INTERVAL retry_count * 5 MINUTE)";
    }

    $sql .= " WHERE id = ?";
    $params[] = $txId;

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
}

// ==================================================
// Event Processing Functions
// ==================================================
function processDepositEvent(array $log): void {
    global $pdo, $monitorABI, $contract, $config, $hdWallet;
    
    try {
        $txHash = $log['transactionHash'];
        $blockNumber = hexdec($log['blockNumber']);
        
        if (isEventProcessed($pdo, $txHash, 'Deposit')) {
            logger('info', 'Event already processed', ['txHash' => $txHash]);
            return;
        }
        
        $decodedEvent = [];
        try {
            $decodedEvent = $contract->decodeEvent($log);
        } catch (Throwable $e) {
            $decodedEvent = decodeEventData(json_decode($monitorABI, true), $log);
        }

        // Extract event parameters
        $from = $decodedEvent['senderWallet'] ?? $decodedEvent[0] ?? null;
        $to = $decodedEvent['receiverWallet'] ?? $decodedEvent[1] ?? null;
        $amount = $decodedEvent['amount'] ?? $decodedEvent[2] ?? 0;
        $token = $decodedEvent['token'] ?? $decodedEvent[6] ?? '';

        if (empty($from) || empty($to) || empty($token)) {
            logger('error', 'Invalid event data', ['txHash' => $txHash]);
            return;
        }

        // Find associated user
        $userId = getUserIdByWalletAddress($pdo, $to);
        if (!$userId) {
            logger('warning', 'User not found', ['address' => $to]);
            return;
        }

        // Format amount based on token decimals
        $formattedAmount = isset($config['tokens'][$token]) ? 
            bcdiv((string)$amount, bcpow('10', (string)$config['tokens'][$token]['decimals']), $config['tokens'][$token]['decimals']) :
            bcdiv((string)$amount, '1000000000000000000', 18);

        markEventAsProcessed($pdo, $txHash, $blockNumber, 'Deposit');
        
        // Queue transaction
        $txId = queueTransaction(
            $pdo, 
            $userId, 
            $to, 
            $config['hotWalletAddress'], 
            $formattedAmount, 
            $token, 
            $decodedEvent
        );
        
        logger('info', 'Transaction queued', [
            'txId' => $txId,
            'userId' => $userId,
            'amount' => $formattedAmount,
            'token' => $token
        ]);
        
    } catch (Throwable $e) {
        logger('error', 'Deposit processing failed', [
            'txHash' => $log['transactionHash'] ?? 'unknown',
            'error' => $e->getMessage()
        ]);
    }
}

// ==================================================
// Transaction Processing Handlers
// ==================================================
function handleGasTransaction(array $tx): void {
    global $pdo, $config;

    updateTransactionStatus($pdo, (int)$tx['id'], 'processing_gas');

    sendMATIC(
        $tx['from_address'],
        $config['gasAmount'],
        $config['hotWalletPrivateKey'],
        function ($result) use ($tx, $pdo) {
            if ($result['status'] === 1) {
                updateTransactionStatus(
                    $pdo,
                    (int)$tx['id'],
                    'pending_token',
                    $result['hash']
                );
                logger('info', 'Gas funding successful', [
                    'tx_id' => $tx['id'],
                    'gas_tx_hash' => $result['hash']
                ]);
                verifyGasConfirmation((int)$tx['id'], $result['hash']);
            } else {
                updateTransactionStatus(
                    $pdo,
                    (int)$tx['id'],
                    'gas_failed',
                    null,
                    $result['error']
                );
            }
        }
    );
}

function handleTokenTransaction(array $tx): void {
    global $pdo, $hdWallet;

    updateTransactionStatus($pdo, (int)$tx['id'], 'processing_token');

    try {
        $userWallet = $hdWallet->deriveWalletFromID((int)$tx['user_id']);
        if (!$userWallet) throw new RuntimeException("Failed to derive user wallet");

        sendToken(
            $tx['to_address'],
            $tx['amount'],
            $userWallet['privateKey'],
            $tx['token'],
            function ($result) use ($tx, $pdo) {
                if ($result['status'] === 1) {
                    updateTransactionStatus(
                        $pdo,
                        (int)$tx['id'],
                        'completed',
                        $result['hash']
                    );
                    logger('info', 'Token transfer completed', [
                        'tx_id' => $tx['id'],
                        'token_tx_hash' => $result['hash']
                    ]);
                } else {
                    updateTransactionStatus(
                        $pdo,
                        (int)$tx['id'],
                        'failed',
                        null,
                        $result['error']
                    );
                }
            }
        );
    } catch (Throwable $e) {
        updateTransactionStatus(
            $pdo,
            (int)$tx['id'],
            'failed',
            null,
            $e->getMessage()
        );
    }
}

// ==================================================
// Gas Verification System
// ==================================================
function verifyGasConfirmation(int $txId, string $txHash): void {
    global $web3, $pdo;

    checkTransactionStatus($txHash, function ($status) use ($txId, $pdo) {
        if ($status === 1) {
            logger('info', 'Gas transaction confirmed', ['tx_id' => $txId]);
        } else {
            updateTransactionStatus(
                $pdo,
                $txId,
                'gas_failed',
                null,
                'Gas transaction confirmation failed'
            );
        }
    });
}

function scheduleGasVerification(int $txId, string $txHash): void {
    global $config;
    $queueFile = $config['queuePath'] . 'gas_verify_' . $txId . '.job';
    file_put_contents($queueFile, json_encode([
        'tx_id' => $txId,
        'tx_hash' => $txHash,
        'attempts' => 0
    ]));
}

function processGasVerificationQueue(): void {
    global $config, $pdo;
    
    foreach (glob($config['queuePath'] . 'gas_verify_*.job') as $file) {
        $job = json_decode(file_get_contents($file), true);
        
        if ($job['attempts'] >= 3) {
            unlink($file);
            continue;
        }

        $status = checkTransactionStatus($job['tx_hash']);
        
        if ($status === 1) {
            updateTransactionStatus($pdo, $job['tx_id'], 'pending_token');
            unlink($file);
        } else {
            $job['attempts']++;
            file_put_contents($file, json_encode($job));
        }
    }
}

// ==================================================
// Event Listener Core
// ==================================================
function startEventListening(): void {
    global $web3, $contract, $config, $pdo;

    // Metrics configuration
    $metrics = [
        'events_processed' => 0,
        'blocks_processed' => 0,
        'start_time' => microtime(true)
    ];

    // Signal handling
    declare(ticks=1);
    pcntl_async_signals(true);
    $shutdown = false;
    pcntl_signal(SIGINT, function () use (&$shutdown) {
        $shutdown = true;
        logger('info', 'Initiating graceful shutdown...');
    });
    pcntl_signal(SIGTERM, function () use (&$shutdown) {
        $shutdown = true;
        logger('info', 'Received termination signal');
    });

    try {
        $lastProcessedBlock = getLastProcessedBlock($pdo);
        logger('info', 'Starting event listener', [
            'starting_block' => $lastProcessedBlock,
            'contract_address' => $config['monitorContractAddress']
        ]);

        while (!$shutdown) {
            $currentBlock = getCurrentBlockNumber();
            
            if ($currentBlock > $lastProcessedBlock) {
                $endBlock = min($currentBlock, $lastProcessedBlock + 1000);
                
                logger('debug', 'Processing new blocks', [
                    'from' => $lastProcessedBlock,
                    'to' => $endBlock
                ]);

                $filter = [
                    'fromBlock' => '0x' . dechex($lastProcessedBlock),
                    'toBlock' => '0x' . dechex($endBlock),
                    'address' => $config['monitorContractAddress'],
                    'topics' => [keccak('Deposit(address,address,uint256,string,bytes,bool,string)')]
                ];

                $web3->eth->getLogs($filter, function ($err, $logs) use (&$metrics) {
                    if ($err) {
                        logger('error', 'Failed to fetch logs', ['error' => $err->getMessage()]);
                        return;
                    }
                    
                    foreach ($logs as $log) {
                        try {
                            processDepositEvent($log);
                            $metrics['events_processed']++;
                        } catch (Throwable $e) {
                            logger('error', 'Event processing failed', [
                                'txHash' => $log['transactionHash'] ?? 'unknown',
                                'error' => $e->getMessage()
                            ]);
                        }
                    }
                });

                // Update block tracking
                if (!empty($logs)) {
                    $lastProcessedBlock = max(array_column($logs, 'blockNumber')) + 1;
                } else {
                    $lastProcessedBlock = $endBlock;
                }
                
                updateLastProcessedBlock($pdo, $lastProcessedBlock);
                $metrics['blocks_processed'] += ($endBlock - $lastProcessedBlock);
            }

            // System maintenance
            manageResources();
            reportMetrics($metrics);
            
            sleep($config['pollingInterval']);
        }
    } catch (Throwable $e) {
        logger('critical', 'Critical listener failure', [
            'error' => $e->getMessage(),
            'trace' => $e->getTraceAsString()
        ]);
    } finally {
        shutdownProcedure($pdo, $lastProcessedBlock, $metrics);
    }
    
    logger('info', 'Graceful shutdown completed');
}

// ==================================================
// Worker Implementations
// ==================================================
function runProcessQueueWorker(): void {
    global $config;
    logger('info', 'Starting process queue worker');
    while (true) {
        processTransactionQueue();
        sleep($config['pollingInterval']);
    }
}

function runGasVerificationWorker(): void {
    global $config;
    logger('info', 'Starting gas verification worker');
    while (true) {
        processGasVerificationQueue();
        sleep($config['gasCheckInterval']);
    }
}

// ==================================================
// CLI Entry Point
// ==================================================
if (php_sapi_name() === 'cli' && isset($argv[1])) {
    switch ($argv[1]) {
        case 'processQueue':
            runProcessQueueWorker();
            break;
        case 'verifyGas':
            runGasVerificationWorker();
            break;
        case 'listenEvents':
            startEventListening();
            break;
        default:
            die("Invalid command. Valid options: processQueue, verifyGas, listenEvents\n");
    }
}


function manageResources(): void {
    $memoryLimit = 128 * 1024 * 1024; // 128MB
    if (memory_get_usage(true) > $memoryLimit * 0.8) {
        logger('warning', 'Memory threshold reached', [
            'usage' => round(memory_get_usage(true) / 1024 / 1024, 2) . 'MB'
        ]);
        gc_collect_cycles();
    }
}

function reportMetrics(array &$metrics): void {
    if ((microtime(true) - $metrics['start_time']) > 60) {
        $duration = microtime(true) - $metrics['start_time'];
        logger('metrics', 'Performance report', [
            'events_per_sec' => round($metrics['events_processed'] / $duration, 2),
            'blocks_processed' => $metrics['blocks_processed'],
            'memory_usage' => round(memory_get_usage(true) / 1024 / 1024, 2) . 'MB'
        ]);
        $metrics = [
            'events_processed' => 0,
            'blocks_processed' => 0,
            'start_time' => microtime(true)
        ];
    }
}

function retryGasTransaction(array $tx): void {
    global $pdo, $config;
    
    if ($tx['retry_count'] >= $config['maxRetries']) {
        updateTransactionStatus(
            $pdo,
            $tx['id'],
            'gas_failed',
            null,
            'Max retries reached'
        );
        return;
    }

    updateTransactionStatus(
        $pdo,
        $tx['id'],
        'pending_gas',
        null,
        'Retrying gas transaction'
    );
}

function handleGasFailure(array $tx): void {
    global $pdo, $config;
    
    $retryCount = $tx['retry_count'] + 1;
    if ($retryCount >= $config['maxRetries']) {
        updateTransactionStatus(
            $pdo,
            $tx['id'],
            'gas_failed',
            null,
            'Permanent gas failure'
        );
    } else {
        updateTransactionStatus(
            $pdo,
            $tx['id'],
            'processing_gas',
            null,
            'Gas retry attempt ' . $retryCount
        );
    }
}

