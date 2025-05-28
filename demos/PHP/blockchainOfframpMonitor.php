<?php
require __DIR__ . '/vendor/autoload.php';
use Web3\Web3;
use Web3\Contract;
use Web3\Providers\HttpProvider;
use Web3\RequestManagers\HttpRequestManager;
use kornrunner\Keccak;

// Configuration
$config = [
    'http_rpc' => 'https://polygon-rpc.com',
    'usdt_contract' => '0xc2132D05D31c914a87C6611C10748AEb04B58e8F', // USDT Polygon
    'hot_wallet' => '0x...', // Your hot wallet address
    'usdt_abi_path' => __DIR__ . '/usdt_abi.json',
    'polling_interval' => 15,
    'log_path' => __DIR__ . '/logs/events.log'
];

// Initialize Web3
$web3 = new Web3(new HttpProvider(new HttpRequestManager($config['http_rpc'])));
$usdtAbi = json_decode(file_get_contents($config['usdt_abi_path']), true);
$usdtContract = new Contract($web3->provider, $usdtAbi);

// Custom memo decoder
function extractMemoFromInput($input) {
    try {
        // Remove 0x prefix
        $rawData = str_replace('0x', '', $input);
        
        // Standard transfer method selector (first 4 bytes)
        $transferSelector = substr($rawData, 0, 8);
        if ($transferSelector !== 'a9059cbb') {
            return null; // Not a transfer transaction
        }

        // Extract parameters (to: 32 bytes, value: 32 bytes)
        $params = substr($rawData, 8, 128); // 64 chars = 32 bytes * 2
        
        // Remaining data is our memo bytes
        $memoHex = substr($rawData, 136); // Skip first 4+32+32 = 68 bytes (136 chars)
        if (empty($memoHex)) return null;

        // Convert to binary and find JSON boundaries
        $binaryData = hex2bin($memoHex);
        $firstBrace = strpos($binaryData, '{');
        $lastBrace = strrpos($binaryData, '}');

        if ($firstBrace === false || $lastBrace === false) {
            return null; // No valid JSON found
        }

        // Extract JSON string
        $jsonString = substr($binaryData, $firstBrace, $lastBrace - $firstBrace + 1);
        return json_decode($jsonString, true);
        
    } catch (Exception $e) {
        return null;
    }
}

function decodeTransferEvent(array $contractAbi, array $log): array {
    // Find Transfer event in ABI
    $transferEventAbi = null;
    foreach ($contractAbi as $item) {
        if (isset($item['type'], $item['name']) && 
            $item['type'] === 'event' && 
            $item['name'] === 'Transfer') {
            $transferEventAbi = $item;
            break;
        }
    }

    if (!$transferEventAbi || !isset($transferEventAbi['inputs'])) {
        throw new \Exception("Transfer event not found in ABI");
    }

    $decoded = [];
    $indexedParams = [];
    $nonIndexedParams = [];

    // Separate indexed and non-indexed parameters
    foreach ($transferEventAbi['inputs'] as $input) {
        if ($input['indexed'] ?? false) {
            $indexedParams[] = $input;
        } else {
            $nonIndexedParams[] = $input;
        }
    }

    // Decode indexed parameters (from, to)
    foreach ($indexedParams as $index => $param) {
        $topicIndex = $index + 1; // topic[0] is event signature
        if (isset($log['topics'][$topicIndex])) {
            $topic = $log['topics'][$topicIndex];
            switch ($param['type']) {
                case 'address':
                    // Address extraction from 32-byte padded topic
                    $decoded[$param['name']] = '0x' . substr($topic, 26);
                    break;
                default:
                    $decoded[$param['name']] = $topic;
            }
        }
    }

    // Decode non-indexed parameters (value)
    if (isset($log['data']) && $log['data'] !== '0x') {
        $data = substr($log['data'], 2); // Remove 0x
        $position = 0;

        foreach ($nonIndexedParams as $param) {
            list($value, $newPosition) = decodeParam($param['type'], $data, $position);
            $decoded[$param['name']] = $value;
            $position = $newPosition;
        }
    }

    return $decoded;
}

// Helper function to decode parameters
function decodeParam(string $type, string &$data, int $position): array {
    // uint256 decoding
    if (str_starts_with($type, 'uint')) {
        $value = hexdec(substr($data, $position * 2, 64));
        return [$value, $position + 32];
    }

    // bytes/string decoding
    if ($type === 'bytes' || $type === 'string') {
        $offset = hexdec(substr($data, $position * 2, 64)) * 2;
        $length = hexdec(substr($data, $offset, 64)) * 2;
        $value = hex2bin(substr($data, $offset + 64, $length));
        return [$value, $position + 32];
    }

    // Default case for other types
    return [hex2bin(substr($data, $position * 2, 64)), $position + 32];
}

// Enhanced Transfer event handler
function handleTransferEvent(array $log): void {
    global $config, $web3, $erc20Abi;

    $web3->eth->getTransactionByHash($log['transactionHash'], 
        function ($err, $tx) use ($log, $config) {
            try {
                if ($err || !$tx || !isset($tx->input)) {
                    throw new Exception("Transaction data unavailable");
                }

                // 1. Decode ERC20 Transfer event
                $decodedEvent = decodeTransferEvent($erc20Abi, $log);
                
                // 2. Validate event structure
                $requiredEventKeys = ['from', 'to', 'value'];
                foreach ($requiredEventKeys as $key) {
                    if (!isset($decodedEvent[$key])) {
                        throw new Exception("Missing event field: $key");
                    }
                }

                // 3. Filter transactions to hot wallet
                if (strtolower($decodedEvent['to']) !== strtolower($config['hot_wallet'])) {
                    return;
                }

                // 4. Extract and validate memo
                $memoData = extractMemoFromInput($tx->input);
                if (empty($memoData) || !isset($memoData['amountBRL'])) {
                    logger('error', 'Invalid memo data', [
                        'tx_hash' => $log['transactionHash'],
                        'input_data' => $tx->input
                    ]);
                    return;
                }

                // 5. Process valid transaction
                processValidTransaction(
                    $decodedEvent['from'],
                    $decodedEvent['value'],
                    $memoData,
                    $log['transactionHash']
                );

            } catch (Throwable $e) {
                logger('error', 'Transfer processing failed', [
                    'tx_hash' => $log['transactionHash'] ?? 'unknown',
                    'error' => $e->getMessage(),
                    'trace' => $e->getTraceAsString()
                ]);
            }
        }
    );
}

// Transaction processing
function processValidTransaction($from, $value, $memo, $txHash) {
    // 1. Find user by from address
    $user = findUserByAddress($from);
    
    // 2. Convert value to decimal (USDT has 6 decimals)
    $amount = bcdiv($value, bcpow(10, 6), 6);
    

    //3. Save to database
    saveTransactionToDB($user['id'], [
        'tx_hash' => $txHash,
        'amount' => $amount,
        'e2e_id' => $memo['e2e'],
        'transaction_key' => $memo['key'],
        'message' => $memo['msg'],
        'datetime' => $memo['datetime']
    ]);

    logger('Transaction processed', [
        'user' => $user['id'],
        'amount' => $amount,
        'e2e' => $memo['e2e']
    ]);
}

// Database functions (implement according to your setup)
function findUserByAddress($address) {
    // Query database to find user by wallet address
    return []; // return user data
}

function saveTransactionToDB($userId, $transactionData) {
    // Insert transaction record into database
}

// Event listener setup
function startEventListener() {
    global $web3, $config;

    $lastBlock = getLastProcessedBlock();
    
    while (true) {
        try {
            $currentBlock = hexdec($web3->eth->blockNumber()->toString());
            
            if ($currentBlock <= $lastBlock) {
                sleep($config['polling_interval']);
                continue;
            }

            // Filter for Transfer events to hot wallet
            $filter = [
                'fromBlock' => '0x' . dechex($lastBlock + 1),
                'toBlock' => '0x' . dechex($currentBlock),
                'address' => $config['usdt_contract'],
                'topics' => [
                    Keccak::hash('Transfer(address,address,uint256)'),
                    null,
                    '0x' . str_pad(substr($config['hot_wallet'], 2), 64, '0', STR_PAD_LEFT)
                ]
            ];

            $web3->eth->getLogs($filter, function ($err, $logs) {
                if ($err) return;
                
                foreach ($logs as $log) {
                    handleTransferEvent($log);
                }
            });

            updateLastProcessedBlock($currentBlock);
            $lastBlock = $currentBlock;

            sleep($config['polling_interval']);

        } catch (Exception $e) {
            sleep(60);
        }
    }
}

// Helper functions
function logger($message, $context = []) {
    global $config;
    file_put_contents(
        $config['log_path'],
        json_encode(['ts' => time(), 'msg' => $message, 'ctx' => $context]) . PHP_EOL,
        FILE_APPEND
    );
}

function getLastProcessedBlock() {
    $file = __DIR__ . '/last_block.txt';
    return file_exists($file) ? (int)file_get_contents($file) : 0;
}

function updateLastProcessedBlock($block) {
    file_put_contents(__DIR__ . '/last_block.txt', $block);
}

// Start listener
startEventListener();