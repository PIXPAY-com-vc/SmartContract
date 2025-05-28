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

/***********************************************************************************************************************
 Para executar o sistema completo:

# Terminal 1 - Listener de eventos
php monitor.php listenEvents

# Terminal 2 - Processador de fila
php monitor.php processQueue

# Terminal 3 - Verificador de gás
php monitor.php verifyGas

# Verificar todos os logs
tail -f logs/$(date +%Y-%m-%d).log

# Filtrar por tipo de log
tail -f logs/$(date +%Y-%m-%d).log | grep 'ERROR'
tail -f logs/$(date +%Y-%m-%d).log | grep 'METRICS'

Para ambiente de produção e robustes de execução:

/* Em ambientes Linux: Crie serviços systemd para cada worker:

# /etc/systemd/system/monitor-processQueue.service
[Unit]
Description=Blockchain Transaction Processor

[Service]
ExecStart=/usr/bin/php /caminho/monitor.php processQueue
Restart=always
EnvironmentFile=/etc/default/monitor

[Install]
WantedBy=multi-user.target

# /etc/systemd/system/monitor-verifyGas.service
[Unit]
Description=Gas Confirmation Verifier

[Service]
ExecStart=/usr/bin/php /caminho/monitor.php verifyGas
Restart=always
EnvironmentFile=/etc/default/monitor

[Install]
WantedBy=multi-user.target

# /etc/systemd/system/monitor-listenEvents.service
[Unit]
Description=Blockchain Event Listener
After=network.target

[Service]
ExecStart=/usr/bin/php /caminho/completo/monitor.php listenEvents
Restart=always
RestartSec=5
User=www-data
Group=www-data
Environment="APP_ENV=production"
WorkingDirectory=/caminho/completo
EnvironmentFile=/etc/default/monitor
# Configuração de segurança
ProtectSystem=full
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target

Controle dos workers

# Recarregar configurações
sudo systemctl daemon-reload

# Iniciar todos os serviços
sudo systemctl start monitor-listenEvents monitor-processQueue monitor-verifyGas

# Habilitar inicialização automática
sudo systemctl enable monitor-listenEvents monitor-processQueue monitor-verifyGas

# Verificar status
systemctl status monitor-listenEvents monitor-processQueue monitor-verifyGas

# Parar todos os serviços
sudo systemctl stop monitor-listenEvents monitor-processQueue monitor-verifyGas

Permissões:

sudo chmod 640 /etc/systemd/system/monitor-*.service
sudo chown root:root /etc/systemd/system/monitor-*.service

variáveis ENV:

# Criar arquivo de ambiente
sudo nano /etc/default/monitor

# Conteúdo:
APP_ENV=production
HOT_WALLET_PRIVATE_KEY=seu_private_key
DB_PASSWORD=sua_senha_db

monitoramento:

# Verificar logs em tempo real
journalctl -u monitor-listenEvents -f

# Estatísticas de memória
journalctl -u monitor-verifyGas --since "1 hour ago" | grep memory_usage

# Health check diário
sudo nano /etc/cron.daily/monitor-check

#!/bin/bash
systemctl is-active -q monitor-listenEvents || systemctl restart monitor-listenEvents
systemctl is-active -q monitor-processQueue || systemctl restart monitor-processQueue
systemctl is-active -q monitor-verifyGas || systemctl restart monitor-verifyGas


Importante: Substitua:

    /caminho/completo/ pelo diretório real do seu projeto
    /usr/bin/php pelo caminho completo do seu PHP (which php)
    Ajuste User e Group conforme sua configuração de servidor
**********************************************************************************************************************/


// Configurações principais
$config = [
    'httpRPC' => "https://polygon-rpc.com",
    'monitorContractAddress' => "0x...", // Endereço do contrato Monitor
    'hotWalletAddress' => "0x...", // Endereço da Hot Wallet
    'hotWalletPrivateKey' => getenv('HOT_WALLET_PRIVATE_KEY'), // Usar variável de ambiente
    'blockConfirmations' => 2, // Número de confirmações necessárias
    'gasAmount' => "0.06", // Quantidade de MATIC para gás
    'maxRetries' => 3, // Número máximo de tentativas
    'retryDelay' => 5, // Delay em segundos entre tentativas
    'maxConcurrentTasks' => 10, // Máximo de tarefas concorrentes
    'pollingInterval' => 10, // Intervalo de verificação em segundos
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
    'queuePath' => __DIR__ . '/queue/', // Pasta para sistema de fila local
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

// Inicializar logger
if (!is_dir($config['logPath'])) {
    mkdir($config['logPath'], 0755, true);
}
if (!is_dir($config['queuePath'])) {
    mkdir($config['queuePath'], 0755, true);
}

if ($argc < 2) {
    die("Uso: php monitor.php <comando>\nComandos disponíveis: processQueue, verifyGas\n");
}


// Inicializar conexão com blockchain
$web3 = new Web3(new HttpProvider(new HttpRequestManager($config['httpRPC'])));
$monitorABI = file_get_contents(__DIR__ . '/monitor.json');
$contract = new Contract($web3->provider, json_decode($monitorABI, true));
$hdWallet = new HDWalletSDK();

// Inicializar conexão com banco de dados
$pdo = new PDO(
    "mysql:host={$config['dbConnection']['host']};dbname={$config['dbConnection']['dbname']}",
    $config['dbConnection']['user'],
    $config['dbConnection']['password'],
    [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
);

// Criar tabelas se não existirem
setupDatabase($pdo);

/**
 * Configura as tabelas do banco de dados
 * @param PDO $pdo
 */
function setupDatabase(PDO $pdo): void {
    // Tabela de transações pendentes
    $pdo->exec("CREATE TABLE IF NOT EXISTS pending_transactions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        from_address VARCHAR(42) NOT NULL,
        to_address VARCHAR(42) NOT NULL,
        amount VARCHAR(50) NOT NULL,
        token VARCHAR(10) NOT NULL,
        tx_hash VARCHAR(66) NULL,
        status ENUM('pending_gas',
        'processing_gas',
        'gas_failed',
        'pending_token',
        'processing_token',
        'completed',
        'failed') NOT NULL DEFAULT 'pending_gas',
        retry_count INT NOT NULL DEFAULT 0,
        next_retry DATETIME NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        error_message TEXT NULL,
        raw_event TEXT NULL,
        INDEX (status),
        INDEX (next_retry)
    )");

    // Tabela de eventos processados
    $pdo->exec("CREATE TABLE IF NOT EXISTS processed_events (
        id INT AUTO_INCREMENT PRIMARY KEY,
        tx_hash VARCHAR(66) NOT NULL,
        block_number INT NOT NULL,
        event_name VARCHAR(50) NOT NULL,
        processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY (tx_hash, event_name)
    )");
    
    // Tabela de estado do processador
    $pdo->exec("CREATE TABLE IF NOT EXISTS monitor_state (
        id INT AUTO_INCREMENT PRIMARY KEY,
        key_name VARCHAR(50) NOT NULL,
        value TEXT NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE KEY (key_name)
    )");
}

/**
 * Função para log estruturado
 * @param string $level
 * @param string $message
 * @param array $context
 */
function logger(string $level, string $message, array $context = []): void {
    global $config;
    
    $logFile = $config['logPath'] . date('Y-m-d') . '.log';
    
    $logEntry = [
        'timestamp' => date('Y-m-d H:i:s'),
        'level' => $level,
        'message' => $message,
        'context' => $context
    ];
    
    file_put_contents(
        $logFile,
        json_encode($logEntry) . PHP_EOL,
        FILE_APPEND
    );
    
    // Também exibir no console se não estiver em produção
    if (getenv('APP_ENV') !== 'production') {
        echo "[{$logEntry['timestamp']}] [{$level}] {$message}" . 
             (!empty($context) ? ' ' . json_encode($context) : '') . PHP_EOL;
    }
}

/**
 * Obtém o último bloco processado do banco de dados
 * @param PDO $pdo
 * @return int
 */
function getLastProcessedBlock(PDO $pdo): int {
    $stmt = $pdo->prepare("SELECT value FROM monitor_state WHERE key_name = 'last_processed_block'");
    $stmt->execute();
    
    if ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        return (int)$row['value'];
    }
    
    // Se não encontrou, obter o bloco atual menos 1000
    $currentBlock = getCurrentBlockNumber();
    $startBlock = max(1, $currentBlock - 1000);
    
    // Inserir o valor inicial
    $stmt = $pdo->prepare("INSERT INTO monitor_state (key_name, value) VALUES ('last_processed_block', :value)");
    $stmt->execute(['value' => $startBlock]);
    
    return $startBlock;
}

/**
 * Atualiza o último bloco processado
 * @param PDO $pdo
 * @param int $blockNumber
 */
function updateLastProcessedBlock(PDO $pdo, int $blockNumber): void {
    $stmt = $pdo->prepare("UPDATE monitor_state SET value = :value WHERE key_name = 'last_processed_block'");
    $stmt->execute(['value' => $blockNumber]);
}

/**
 * Obtém o número do bloco atual
 * @return int
 */
function getCurrentBlockNumber(): int {
    global $web3;
    
    $currenBlock = null;
    $web3->eth->blockNumber(function ($err, $blockNumber) use (&$currentBlock) {
        if ($err !== null) {
            echo "Erro ao obter número do bloco: " . $err->getMessage() . PHP_EOL;
            return;
        }
        return $blockNumber;
        echo "Bloco atual >> " . $currentBlock . PHP_EOL;
    });
    
    if ($currentBlock === null) {
        echo "Falha ao obter o número do bloco atual" . PHP_EOL;
        return 0;
    }
}

/**
 * Verifica se um evento já foi processado
 * @param PDO $pdo
 * @param string $txHash
 * @param string $eventName
 * @return bool
 */
function isEventProcessed(PDO $pdo, string $txHash, string $eventName): bool {
    $stmt = $pdo->prepare("SELECT id FROM processed_events WHERE tx_hash = :tx_hash AND event_name = :event_name");
    $stmt->execute([
        'tx_hash' => $txHash,
        'event_name' => $eventName
    ]);
    
    return $stmt->fetch() !== false;
}

/**
 * Marca um evento como processado
 * @param PDO $pdo
 * @param string $txHash
 * @param int $blockNumber
 * @param string $eventName
 */
function markEventAsProcessed(PDO $pdo, string $txHash, int $blockNumber, string $eventName): void {
    $stmt = $pdo->prepare("INSERT IGNORE INTO processed_events (tx_hash, block_number, event_name) VALUES (:tx_hash, :block_number, :event_name)");
    $stmt->execute([
        'tx_hash' => $txHash,
        'block_number' => $blockNumber,
        'event_name' => $eventName
    ]);
}

/**
 * Função para buscar o ID do usuário com base no endereço da carteira
 * @param PDO $pdo
 * @param string $walletAddress
 * @return int|null
 */
function getUserIdByWalletAddress(PDO $pdo, string $walletAddress): ?int {
    try {
        $stmt = $pdo->prepare("SELECT user_id FROM user_wallets WHERE wallet_address = :address");
        $stmt->execute(['address' => strtolower($walletAddress)]);
        
        if ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
            return (int) $row['user_id'];
        }
        
        return null;
    } catch (\PDOException $e) {
        logger('error', 'Erro ao consultar banco de dados', ['error' => $e->getMessage()]);
        return null;
    }
}

/**
 * Decodifica os parâmetros de eventos
 * @param array $types
 * @param string $data
 * @return array
 */
function decodeEventData(array $contractAbi, array $log): array {
    // Encontrar o evento Deposit no ABI
    $eventAbi = null;
    foreach ($contractAbi as $item) {
        if (isset($item['type'], $item['name']) && 
            $item['type'] === 'event' && 
            $item['name'] === 'Deposit') {
            $eventAbi = $item;
            break;
        }
    }

    if (!$eventAbi || !isset($eventAbi['inputs'])) {
        throw new \Exception("Evento Deposit não encontrado no ABI");
    }

    $decoded = [];
    $indexedParams = [];
    $nonIndexedParams = [];

    // Separar parâmetros indexados e não indexados
    foreach ($eventAbi['inputs'] as $input) {
        if ($input['indexed'] ?? false) {
            $indexedParams[] = $input;
        } else {
            $nonIndexedParams[] = $input;
        }
    }

    // Decodificar tópicos indexados
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

    // Decodificar dados não indexados
    if (isset($log['data']) && $log['data'] !== '0x') {
        $data = substr($log['data'], 2); // Remove 0x
        $position = 0;
        
        foreach ($nonIndexedParams as $param) {
            list($value, $newPos) = decodeParam($param['type'], $data, $position);
            $decoded[$param['name']] = $value;
            $position = $newPos;
        }
    }

    return $decoded;
}

/**
 * Decodifica um parâmetro individual
 * @param string $type
 * @param string $data
 * @param int $pos
 * @return array
 */
function decodeParam(string $type, string &$data, int $pos): array {
    $staticTypes = [
        'address' => 32, 
        'bool' => 32,
        'uint256' => 32,
        'int256' => 32
    ];

    // Tipos estáticos
    if (isset($staticTypes[$type])) {
        $bytes = substr($data, $pos * 2, $staticTypes[$type] * 2);
        $pos += $staticTypes[$type];

        switch ($type) {
            case 'address':
                // Extrair últimos 40 caracteres (20 bytes) removendo zeros à esquerda
                $address = '0x' . substr($bytes, -40);
                return [$address, $pos];
                
            case 'bool':
                $value = hexdec($bytes) !== 0;
                return [$value, $pos];
                
            case 'uint256':
                $value = hexdec($bytes);
                return [$value, $pos];
                
            default:
                return ['0x' . $bytes, $pos];
        }
    }

    // Tipos dinâmicos (string/bytes)
    if ($type === 'string' || $type === 'bytes') {
        $offsetBytes = (int) hexdec(substr($data, $pos * 2, 64));
        $offset = $offsetBytes * 2;
        $pos += 32;

        $lengthBytes = (int) hexdec(substr($data, $offset, 64));
        $length = $lengthBytes * 2;
        $offset += 64;

        $valueData = substr($data, $offset, $length);

        if ($type === 'string') {
            return [hex2bin($valueData), $pos];
        }

        $decoded = hex2bin($valueData);
        if (function_exists('json_validate') && json_validate($decoded)) { 
            return [json_decode($decoded, true), $pos];
        }
        return [$decoded, $pos];
    }

    throw new \Exception("Tipo não suportado: $type");
}

/**
 * Envia MATIC para cobrir custos de gás
 * @param string $toAddress
 * @param string $amount
 * @param string $privateKey
 * @return array
 */
function sendMATIC(string $toAddress, string $amount, string $privateKey, callable $callback): void {
    global $web3, $hdWallet;

    $fromAddress = $hdWallet->getAddressFromPrivateKey($privateKey);

    // Obter nonce
    $web3->eth->getTransactionCount($fromAddress, 'pending', function ($err, $result) use ($callback, $fromAddress, $toAddress, $amount, $privateKey) {
        if ($err !== null) {
            logger('error', 'Erro ao obter nonce', ['error' => $err->getMessage()]);
            $callback(["status" => 0, "error" => $err->getMessage()]);
            return;
        }
        
        $nonce = $result->toString();

        // Obter gasPrice
        $web3->eth->gasPrice(function ($err, $gasPriceResult) use ($nonce, $callback, $fromAddress, $toAddress, $amount, $privateKey) {
            if ($err !== null) {
                logger('error', 'Erro ao obter gas price', ['error' => $err->getMessage()]);
                $callback(["status" => 0, "error" => $err->getMessage()]);
                return;
            }

            $gasPrice = hexdec($gasPriceResult->toString());
            $gasPriceIncreased = (int)($gasPrice * 1.2) / 100;

            // Converter valor para Wei
            $valueInWei = bcmul($amount, "1000000000000000000");

            // Criar transação
            $transaction = new Transaction([
                'from' => $fromAddress,
                'nonce' => '0x' . dechex($nonce),
                'gasPrice' => '0x' . dechex($gasPriceIncreased),
                'gas' => '0x5208',
                'to' => $toAddress,
                'value' => '0x' . dechex((int)$valueInWei),
                'chainId' => 137,
                'data' => '0x'
            ]);

            try {
                // Assinar transação
                $signedTx = $transaction->sign($privateKey);

                // Enviar transação
                $web3->eth->sendRawTransaction('0x' . $signedTx, function ($err, $txResult) use ($callback, $fromAddress, $toAddress, $amount) {
                    if ($err !== null) {
                        logger('error', 'Erro ao enviar MATIC', [
                            'error' => $err->getMessage(),
                            'to' => $toAddress,
                            'amount' => $amount
                        ]);
                        $callback(["status" => 0, "error" => $err->getMessage()]);
                        return;
                    }

                    $txHash = $txResult->toString();
                    logger('info', 'MATIC enviado com sucesso', [
                        'from' => $fromAddress,
                        'to' => $toAddress,
                        'amount' => $amount,
                        'txHash' => $txHash
                    ]);
                    $callback(["status" => 1, "hash" => $txHash]);
                });
            } catch (\Throwable $e) {
                logger('error', 'Erro ao assinar transação', ['error' => $e->getMessage()]);
                $callback(["status" => 0, "error" => $e->getMessage()]);
            }
        });
    });
}


/**
* Envia USDT ou outro token ERC20
* @param string $toAddress
* @param string $amount
* @param string $privateKey
* @param string $tokenSymbol
* @return array
*/
function sendToken(string $toAddress, string $amount, string $privateKey, string $tokenSymbol, callable $callback): void {
    global $web3, $hdWallet, $config;

    try {
        if (!isset($config['tokens'][$tokenSymbol])) {
            throw new \Exception("Token não configurado: {$tokenSymbol}");
        }

        $tokenConfig = $config['tokens'][$tokenSymbol];
        $tokenAddress = $tokenConfig['address'];
        $decimals = $tokenConfig['decimals'];

        $tokenAbi = json_decode('[
            {
                "constant": false,
                "inputs": [
                    {"name": "_to", "type": "address"},
                    {"name": "_value", "type": "uint256"}
                ],
                "name": "transfer",
                "outputs": [{"name": "", "type": "bool"}],
                "type": "function"
            }
        ]', true);

        $tokenContract = new Contract($web3->provider, $tokenAbi);
        $fromAddress = $hdWallet->getAddressFromPrivateKey($privateKey);
        $valueInSmallestUnit = bcmul($amount, bcpow("10", $decimals));
        $toAddressFormatted = strtolower(str_replace('0x', '', $toAddress));

        $web3->eth->getTransactionCount($fromAddress, 'pending', function ($err, $nonceResult) use ($callback, $fromAddress, $toAddress, $toAddressFormatted, $amount, $valueInSmallestUnit, $privateKey, $tokenAddress, $decimals, $tokenContract, $tokenSymbol) {
            if ($err !== null) {
                logger('error', 'Erro ao obter nonce', ['error' => $err->getMessage()]);
                $callback(["status" => 0, "error" => $err->getMessage()]);
                return;
            }

            $nonce = $result->toString();
            $methodSelector = '0xa9059cbb';
            $addressPadded = str_pad($toAddressFormatted, 64, '0', STR_PAD_LEFT);
            $valuePadded = str_pad(dechex($valueInSmallestUnit), 64, '0', STR_PAD_LEFT);
            $data = $methodSelector . $addressPadded . $valuePadded;

            $web3->eth->gasPrice(function ($err, $gasPriceResult) use ($nonce, $callback, $data, $fromAddress, $toAddress, $amount, $privateKey, $tokenAddress) {
                if ($err !== null) {
                    logger('error', 'Erro ao obter gas price', ['error' => $err->getMessage()]);
                    $callback(["status" => 0, "error" => $err->getMessage()]);
                    return;
                }

                $gasPrice = hexdec($gasPriceResult->toString());
                $gasPriceIncreased = (int)($gasPrice * 1.2) / 100;


                $transaction = new Transaction([
                    'from' => $fromAddress,
                    'nonce' => '0x' . dechex($nonce),
                    'gasPrice' => '0x' . dechex($gasPriceIncreased),
                    'gas' => '0x' . dechex(800000),
                    'to' => $tokenAddress,
                    'value' => '0x0',
                    'data' => '0x' . $data,
                    'chainId' => 137
                ]);

                try {
                    $signedTx = $transaction->sign($privateKey);
                    
    
                    $web3->eth->sendRawTransaction('0x' . $signedTx, function ($err, $txResult) use ($callback, $fromAddress, $toAddress, $amount, $tokenSymbol) {
                        if ($err !== null) {
                            logger('error', "Erro ao enviar token {$tokenSymbol}", [
                                'error' => $err->getMessage(),
                                'to' => $toAddress,
                                'amount' => $amount
                            ]);
                            $callback(["status" => 0, "error" => $err->getMessage()]);
                            return;
                        }

                        $txHash = $txResult->toString();
                        logger('info', "Token {$tokenSymbol} enviado com sucesso", [
                            'from' => $fromAddress,
                            'to' => $toAddress,
                            'amount' => $amount,
                            'token' => $tokenSymbol,
                            'txHash' => $txHash
                        ]);
                        $callback(["status" => 1, "hash" => $txHash]);
                    });
                } catch (\Throwable $e) {
                    $callback(["status" => 0, "error" => $e->getMessage()]);
                }
            });
        });
    } catch (\Throwable $e) {
        $callback(["status" => 0, "error" => $e->getMessage()]);
    }
}


/**
* Verifica o status de uma transação
* @param string $txHash
* @return int|null 0=pendente, 1=sucesso, 2=falha, null=erro
*/
function checkTransactionStatus(string $txHash, callable $callback): void {
    global $web3;
    
    $web3->eth->getTransactionReceipt($txHash, function ($err, $receipt) use ($callback) {
        if ($err !== null) {
            $callback(null);
            return;
        }
        
        $status = null;
        if ($receipt !== null) {
            $status = isset($receipt->status) ? hexdec($receipt->status) : 1;
        }
        
        $callback($status);
    });
}

/**
* Adiciona uma transação à fila de processamento
* @param PDO $pdo
* @param int $userId
* @param string $fromAddress
* @param string $toAddress
* @param string $amount
* @param string $token
* @param array $rawEvent
* @return int ID da transação pendente
*/
function queueTransaction(PDO $pdo, int $userId, string $fromAddress, string $toAddress, string $amount, string $token, array $rawEvent): int {
   $stmt = $pdo->prepare("INSERT INTO pending_transactions 
       (user_id, from_address, to_address, amount, token, status, raw_event) 
       VALUES (:user_id, :from_address, :to_address, :amount, :token, 'pending', :raw_event)");
   
   $stmt->execute([
       'user_id' => $userId,
       'from_address' => $fromAddress,
       'to_address' => $toAddress,
       'amount' => $amount,
       'token' => $token,
       'raw_event' => json_encode($rawEvent)
   ]);
   
   return (int)$pdo->lastInsertId();
}

/**
* Atualiza o status de uma transação na fila
* @param PDO $pdo
* @param int $txId
* @param string $status
* @param string|null $txHash
* @param string|null $errorMessage
*/
function updateTransactionStatus(PDO $pdo, int $txId, string $status, ?string $txHash = null, ?string $errorMessage = null): void {
   $params = ['id' => $txId, 'status' => $status];
   $sql = "UPDATE pending_transactions SET status = :status";
   
   if ($txHash !== null) {
       $sql .= ", tx_hash = :tx_hash";
       $params['tx_hash'] = $txHash;
   }
   
   if ($errorMessage !== null) {
       $sql .= ", error_message = :error_message";
       $params['error_message'] = $errorMessage;
   }
   
   if ($status === 'failed') {
       $sql .= ", retry_count = retry_count + 1, next_retry = DATE_ADD(NOW(), INTERVAL (retry_count * 5) MINUTE)";
   }
   
   $sql .= " WHERE id = :id";
   
   $stmt = $pdo->prepare($sql);
   $stmt->execute($params);
}

/**
* Processa eventos Deposit do contrato
* @param array $log
*/
function processDepositEvent(array $log): void {
   global $pdo, $monitorABI, $contract, $config, $hdWallet;
   
   try {
       $txHash = $log['transactionHash'];
       $blockNumber = hexdec($log['blockNumber']);
       
       // Verificar se este evento já foi processado
       if (isEventProcessed($pdo, $txHash, 'Deposit')) {
           logger('info', 'Evento já processado, ignorando', ['txHash' => $txHash]);
           return;
       }
       
       // Decodificar o evento
       $decodedEvent = [];
       
       try {
           // Primeiro tenta usar o método do contrato
           $decodedEvent = $contract->decodeEvent($log);
       } catch (\Throwable $e) {
           // Se falhar, usa nossa função de decodificação personalizada
           $decodedEvent = decodeEventData(json_decode($monitorABI, true), $log);
       }
       
       // Extrair informações do evento
       $from = $decodedEvent['senderWallet'] ?? $decodedEvent[0] ?? null;
       $to = $decodedEvent['receiverWallet'] ?? $decodedEvent[1] ?? null;
       $amount = $decodedEvent['amount'] ?? $decodedEvent[2] ?? 0;
       $msgId = $decodedEvent['msgId'] ?? $decodedEvent[3] ?? '';
       $message = $decodedEvent['message'] ?? $decodedEvent[4] ?? '';
       $encrypt = $decodedEvent['encrypt'] ?? $decodedEvent[5] ?? false;
       $token = $decodedEvent['token'] ?? $decodedEvent[6] ?? '';
       
       // Validar dados essenciais
       if (empty($from) || empty($to) || empty($token)) {
           logger('error', 'Dados do evento incompletos', [
               'txHash' => $txHash,
               'blockNumber' => $blockNumber,
               'decodedEvent' => $decodedEvent
           ]);
           return;
       }
       
       // Adicionar metadados ao evento
       $decodedEvent['blockNumber'] = $blockNumber;
       $decodedEvent['transactionHash'] = $txHash;
       
       logger('info', 'Evento Deposit detectado', [
           'from' => $from,
           'to' => $to,
           'amount' => $amount,
           'token' => $token,
           'blockNumber' => $blockNumber,
           'txHash' => $txHash
       ]);
       
       // Obter o ID do usuário
       $userId = getUserIdByWalletAddress($pdo, $to);
       
       if (!$userId) {
           logger('warning', 'Usuário não encontrado para o endereço', ['to' => $to]);
           return;
       }
       
    // Adicione aqui a lógica para atualizar o saldo do usuário em seu banco de dados
    // Por exemplo:
    // updateUserBalance($userId, $amount, $token);

       // Formatar o valor
       $formattedAmount = '0'; 
       if (isset($config['tokens'][$token]) && $token !== 'MATIC') {
           $decimals = $config['tokens'][$token]['decimals'];
           $formattedAmount = bcdiv((string)$amount, bcpow('10', (string)$decimals), $decimals);
       } else {
           // Para MATIC ou tokens não configurados
           $formattedAmount = bcdiv((string)$amount, '1000000000000000000', 18);
       }
       
       // Marcar o evento como processado
       markEventAsProcessed($pdo, $txHash, $blockNumber, 'Deposit');
       
       // Adicionar à fila de processamento
       $txId = queueTransaction(
           $pdo, 
           $userId, 
           $to, 
           $config['hotWalletAddress'], 
           $formattedAmount, 
           $token, 
           $decodedEvent
       );
       
       logger('info', 'Transação adicionada à fila (aguardando envio de gás)', [
           'txId' => $txId,
           'userId' => $userId,
           'amount' => $formattedAmount,
           'token' => $token,
           'status' => 'pending_gas'
       ]);
       
   } catch (\Throwable $e) {
       logger('error', 'Erro ao processar evento Deposit', [
           'txHash' => $log['transactionHash'] ?? 'unknown',
           'error' => $e->getMessage()
       ]);
   }
}

/**
* Processa as transações pendentes na fila
*/
function processTransactionQueue(): void {
    global $pdo, $config;

    $stmt = $pdo->prepare("SELECT * FROM pending_transactions 
        WHERE (status = 'pending_gas' OR status = 'pending_token' 
               OR (status IN ('gas_failed', 'failed') AND retry_count < :max_retries AND next_retry <= NOW()))
        ORDER BY id ASC 
        LIMIT :limit");
    
    $stmt->bindValue(':max_retries', $config['maxRetries'], PDO::PARAM_INT);
    $stmt->bindValue(':limit', $config['maxConcurrentTasks'], PDO::PARAM_INT);
    $stmt->execute();
    
    while ($tx = $stmt->fetch(PDO::FETCH_ASSOC)) {
        try {
            if ($tx['status'] === 'pending_gas') {
                handleGasTransaction($tx);
            } elseif ($tx['status'] === 'pending_token') {
                handleTokenTransaction($tx);
            } elseif ($tx['status'] === 'gas_failed') {
                retryGasTransaction($tx);
            }
        } catch (\Throwable $e) {
            logger('error', 'Erro no processamento da transação', [
                'tx_id' => $tx['id'],
                'error' => $e->getMessage()
            ]);
        }
    }
}

function getMATICBalance(string $address, callable $callback): void {
    global $web3;
    
    $web3->eth->getBalance($address, function ($err, $result) use ($callback) {
        if ($err !== null) {
            logger('error', 'Erro ao obter saldo', ['error' => $err->getMessage()]);
            $callback(null);
            return;
        }
        
        $balanceInWei = hexdec($result->toString());
        $balanceInMATIC = bcdiv($balanceInWei, '1000000000000000000', 6);
        $callback($balanceInMATIC);
    });
}

function handleGasTransaction(array $tx): void {
    global $pdo, $config;

    updateTransactionStatus($pdo, (int)$tx['id'], 'processing_gas');

    getMATICBalance($tx['from_address'], function ($balance) use ($tx, $pdo, $config) {
        if ($balance === null) {
            updateTransactionStatus(
                $pdo,
                (int)$tx['id'],
                'gas_failed',
                null,
                'Erro ao verificar saldo'
            );
            return;
        }

        $minimumBalance = '0.05';
        if (bccomp($balance, $minimumBalance, 6) >= 0) {
            logger('info', 'Saldo suficiente de MATIC', [
                'tx_id' => $tx['id'],
                'balance' => $balance,
                'required' => $minimumBalance
            ]);
            updateTransactionStatus(
                $pdo,
                (int)$tx['id'],
                'pending_token'
            );
            return;
        }

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
                    
                    logger('info', 'MATIC enviado para custódia de gás', [
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
    });
}

function handleTokenTransaction(array $tx): void {
    global $pdo, $hdWallet;

    updateTransactionStatus($pdo, (int)$tx['id'], 'processing_token');

    try {
        $userWallet = $hdWallet->deriveWalletFromID((int)$tx['user_id']);
        if (!$userWallet) throw new Exception("Falha ao obter chave do usuário");

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
                    
                    logger('info', 'Token transferido com sucesso', [
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

    } catch (\Throwable $e) {
        updateTransactionStatus(
            $pdo,
            (int)$tx['id'],
            'failed',
            null,
            $e->getMessage()
        );
    }
}

function verifyGasConfirmation(int $txId, string $txHash): void {
    global $web3, $pdo;

    checkTransactionStatus($txHash, function ($status) use ($txId, $pdo) {
        if ($status === 1) {
            logger('info', 'Gas confirmado', ['tx_id' => $txId]);
        } else {
            updateTransactionStatus(
                $pdo,
                $txId,
                'gas_failed',
                null,
                'Falha na confirmação do gas'
            );
        }
    });
}

function scheduleGasVerification(int $txId, string $txHash): void {
    $queueFile = $config['queuePath'] . 'gas_verify_' . $txId . '.job';
    file_put_contents($queueFile, json_encode([
        'tx_id' => $txId,
        'tx_hash' => $txHash,
        'attempts' => 0
    ]));
}

// Crie um worker separado para processar a fila de verificações
function processGasVerificationQueue(): void {
    global $config;
    
    foreach (glob($config['queuePath'] . 'gas_verify_*.job') as $file) {
        $job = json_decode(file_get_contents($file), true);
        
        if ($job['attempts'] >= 3) {
            unlink($file);
            continue;
        }

        $status = checkTransactionStatus($job['tx_hash']);
        
        if ($status === 1) {
            // Atualizar status no banco
            updateTransactionStatus($pdo, $job['tx_id'], 'pending_token');
            unlink($file);
        } else {
            $job['attempts']++;
            file_put_contents($file, json_encode($job));
        }
    }
}

/**
 * Inicia a escuta contínua de eventos da blockchain
 */
function startEventListening(): void {
    global $web3, $contract, $monitorContractAddress, $pdo, $config;

    // Configuração de controle
    $maxBlocksPerRequest = 1000;
    $shutdown = false;
    $metrics = [
        'events_processed' => 0,
        'blocks_processed' => 0,
        'start_time' => microtime(true)
    ];

    // Registrar handlers para desligamento gracioso
    pcntl_async_signals(true);
    pcntl_signal(SIGINT, function () use (&$shutdown) {
        $shutdown = true;
        logger('info', 'Iniciando desligamento gracioso...');
    });
    pcntl_signal(SIGTERM, function () use (&$shutdown) {
        $shutdown = true;
        logger('info', 'Recebido sinal de término');
    });

    try {
        $lastProcessedBlock = getLastProcessedBlock($pdo);
        logger('info', 'Iniciando escuta de eventos', [
            'starting_block' => $lastProcessedBlock,
            'contract_address' => $monitorContractAddress
        ]);

        while (!$shutdown) {
            $currentBlock = getCurrentBlockNumber();
            
            // Controle de faixa de blocos para evitar sobrecarga
            if ($currentBlock > $lastProcessedBlock) {
                $endBlock = min($currentBlock, $lastProcessedBlock + $maxBlocksPerRequest);
                
                logger('debug', 'Verificando novos blocos', [
                    'from' => $lastProcessedBlock,
                    'to' => $endBlock
                ]);

                $filter = [
                    'fromBlock' => '0x' . dechex($lastProcessedBlock),
                    'toBlock' => '0x' . dechex($endBlock),
                    'address' => $monitorContractAddress,
                    'topics' => [getEventSignature()]
                ];

                // Buscar logs de eventos
                $logs = fetchLogsWithRetry($web3, $filter);
                
                // Processar cada evento
                foreach ($logs as $log) {
                    try {
                        processDepositEvent($log);
                        $metrics['events_processed']++;
                    } catch (\Throwable $e) {
                        logger('error', 'Falha ao processar evento', [
                            'txHash' => $log['transactionHash'] ?? 'unknown',
                            'error' => $e->getMessage()
                        ]);
                    }
                }

                // Atualizar último bloco processado
                if (!empty($logs)) {
                    $lastProcessedBlock = max(array_column($logs, 'blockNumber')) + 1;
                } else {
                    $lastProcessedBlock = $endBlock;
                }
                
                updateLastProcessedBlock($pdo, $lastProcessedBlock);
                $metrics['blocks_processed'] += ($endBlock - $lastProcessedBlock);
            }

            // Gerenciamento de recursos
            manageResources();
            
            // Reportar métricas periodicamente
            reportMetrics($metrics);
            
            // Intervalo entre verificações
            sleep($config['pollingInterval']);
        }
    } catch (\Throwable $e) {
        logger('critical', 'Falha catastrófica no listener', [
            'error' => $e->getMessage(),
            'trace' => $e->getTraceAsString()
        ]);
    } finally {
        shutdownProcedure($pdo, $lastProcessedBlock, $metrics);
    }
}

// Funções auxiliares adicionais
function getEventSignature(): string {
    $eventSignature = 'Deposit(address,address,uint256,string,bytes,bool,string)';
    return '0x' . keccak256($eventSignature);
}

function fetchLogsWithRetry($web3, array $filter, int $maxRetries = 3): array {
    $attempt = 0;
    while ($attempt < $maxRetries) {
        try {
            $logs = $web3->eth->getLogs($filter);
            return $logs ?? [];
        } catch (\Throwable $e) {
            $attempt++;
            logger('warning', 'Falha ao buscar logs', [
                'attempt' => $attempt,
                'error' => $e->getMessage()
            ]);
            sleep(pow(2, $attempt)); // Backoff exponencial
        }
    }
    return [];
}

function manageResources(): void {
    $memoryLimit = 128 * 1024 * 1024; // 128MB
    if (memory_get_usage(true) > $memoryLimit * 0.8) {
        logger('warning', 'Gerenciamento de memória ativado', [
            'usage' => round(memory_get_usage(true) / 1024 / 1024, 2) . 'MB'
        ]);
        gc_collect_cycles();
    }
}

function reportMetrics(array &$metrics): void {
    if ((microtime(true) - $metrics['start_time']) > 60) { // Reportar a cada minuto
        $duration = microtime(true) - $metrics['start_time'];
        logger('metrics', 'Estatísticas de desempenho', [
            'events_per_second' => round($metrics['events_processed'] / $duration, 2),
            'blocks_processed' => $metrics['blocks_processed'],
            'memory_usage' => round(memory_get_usage(true) / 1024 / 1024, 2) . 'MB'
        ]);
        
        // Resetar métricas
        $metrics = [
            'events_processed' => 0,
            'blocks_processed' => 0,
            'start_time' => microtime(true)
        ];
    }
}

function shutdownProcedure(PDO $pdo, int $lastBlock, array $metrics): void {
    logger('info', 'Executando procedimento de desligamento', [
        'last_processed_block' => $lastBlock,
        'events_processed' => $metrics['events_processed']
    ]);
    
    try {
        updateLastProcessedBlock($pdo, $lastBlock);
    } catch (\Throwable $e) {
        logger('critical', 'Falha ao salvar último bloco', [
            'error' => $e->getMessage()
        ]);
    }
}


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
            die("Comando inválido!\n");
    }
}


/**
 * Worker principal para processar a fila de transações
 */
function runProcessQueueWorker(): void {
    global $config;
    
    logger('info', 'Iniciando worker processQueue');
    
    while (true) {
        processTransactionQueue(); // Função que mostrei anteriormente
        sleep($config['pollingInterval']); // Intervalo entre verificações
    }
}

/**
 * Worker especializado em verificar confirmações de gás
 */
function runGasVerificationWorker(): void {
    global $config;
    
    logger('info', 'Iniciando worker verifyGas');
    
    while (true) {
        processGasVerificationQueue(); // Função de verificação
        sleep($config['gasCheckInterval'] ?? 5); // Intervalo específico
    }
}


function processGasVerificationQueue(): void {
    global $config, $pdo;

    // Busca transações com gas enviado mas não confirmado
    $stmt = $pdo->prepare("SELECT * FROM pending_transactions 
        WHERE status = 'processing_gas' 
        AND created_at < DATE_SUB(NOW(), INTERVAL 90 SECOND)
        LIMIT :limit");
    
    $stmt->bindValue(':limit', $config['maxConcurrentTasks'], PDO::PARAM_INT);
    $stmt->execute();
    
    foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $tx) {
        $status = checkTransactionStatus($tx['tx_hash']);
        
        if ($status === 1) {
            // Atualiza para pending_token se confirmado
            updateTransactionStatus(
                $pdo,
                $tx['id'],
                'pending_token'
            );
            
            logger('info', 'Confirmação de gás bem sucedida', [
                'tx_id' => $tx['id'],
                'confirmations' => $config['blockConfirmations']
            ]);
            
        } elseif ($status === 0 || $status === null) {
            // Marcar como falha após várias tentativas
            handleGasFailure($tx);
        }
    }
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
            'Falha definitiva no envio de gás'
        );
    } else {
        updateTransactionStatus(
            $pdo,
            $tx['id'],
            'processing_gas',
            null,
            'Retentativa de confirmação de gás'
        );
    }
}
