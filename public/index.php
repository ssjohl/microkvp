<?php

require __DIR__ . '/../vendor/autoload.php';

// Load the environment variables from the .env file
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/../');
$dotenv->load();

// MySQL database credentials
define('DB_HOST', $_ENV['DB_HOST']);
define('DB_NAME', $_ENV['DB_NAME']);
define('DB_USERNAME', $_ENV['DB_USERNAME']);
define('DB_PASSWORD', $_ENV['DB_PASSWORD']);
define('ADMIN_TOKEN', $_ENV['ADMIN_TOKEN']);

// Get App ID from Token
function appIdFromToken($token) {
    $db = Flight::db();
    $stmt = $db->prepare('SELECT id FROM apps WHERE token = :token LIMIT 1');
    $stmt->bindParam(':token', $token);
    $stmt->execute();
    $app = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$app) {
        Flight::halt(404, 'App not found');
    }

    return $app['id'];
}

// Get App ID from Token
function tokenFromAppID($id) {
    $db = Flight::db();
    $stmt = $db->prepare('SELECT token FROM apps WHERE id = :id LIMIT 1');
    $stmt->bindParam(':id', $id);
    $stmt->execute();
    $app = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$app) {
        Flight::halt(404, 'App not found');
    }

    return $app['token'];
}

// Define a middleware function to check the bearer token
function checkStaticBearerToken() {
    if ($_GET['token'] ?? "" === ADMIN_TOKEN) {
        return;
    }
    if ((!isset($_SERVER['HTTP_AUTHORIZATION']) || $_SERVER['HTTP_AUTHORIZATION'] !== 'Bearer ' . ADMIN_TOKEN)) {
        Flight::halt(401, 'Unauthorized');
    }
}

// Define a middleware function to check the bearer token
function checkAppBearerToken() {
    $token = "";
    if (isset($_GET['token'])) {
        $token = $_GET['token'];
    }
    if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
        $token = explode(' ', $_SERVER['HTTP_AUTHORIZATION'], 2)[1];
    }
    return appIdFromToken($token);
}

// MySQL database connection
Flight::register('db', 'PDO', array("mysql:host=" . DB_HOST . ";dbname=" . DB_NAME, DB_USERNAME, DB_PASSWORD),
    function ($db) {
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    }
);

// Test
Flight::route('GET|POST /test', function() {
    checkStaticBearerToken();

    echo 'I received either a GET or a POST request.';
});

// Init Database
Flight::route('POST /init', function() {
    checkStaticBearerToken();

    Flight::db()->exec('CREATE TABLE IF NOT EXISTS apps (
        id INT UNSIGNED AUTO_INCREMENT,
        name VARCHAR(255) NOT NULL,
        enabled TINYINT(1) NOT NULL DEFAULT 1,
        token VARCHAR(255) NOT NULL,
        PRIMARY KEY (id)
    )');

    // Create the kv table if it doesn't exist
    Flight::db()->exec('CREATE TABLE IF NOT EXISTS kv (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        app_id INT UNSIGNED NOT NULL,
        key_name VARCHAR(255) NOT NULL,
        value TEXT NOT NULL,
        UNIQUE KEY (app_id, key_name),
        FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE
    )');
});

// API endpoint for listing apps
Flight::route('GET /apps', function () {
    checkStaticBearerToken();

    // Retrieve all apps from the database
    $db = Flight::db();
    $stmt = $db->prepare("SELECT * FROM apps");
    $stmt->execute();
    $apps = $stmt->fetchAll(PDO::FETCH_ASSOC);

    Flight::json($apps);
});

// API endpoint for creating/updating an app
Flight::route('POST /apps', function () {
    checkStaticBearerToken();

    // Retrieve data from the request body
    $request_body = Flight::request()->getBody();
    $app_data = json_decode($request_body, true);

    // Add default values for enabled and token
    if (!isset($app_data['enabled'])) {
        $app_data['enabled'] = true;
    }
    if (!isset($app_data['token'])) {
        $app_data['token'] = bin2hex(random_bytes(16));
    }

    // Validate app data
    if (!isset($app_data['name']) || !isset($app_data['enabled']) || !isset($app_data['token'])) {
        Flight::json(array('message' => 'Invalid data'), 400);
        return;
    }

    // Check if the app already exists in the database
    $db = Flight::db();
    $stmt = $db->prepare("SELECT * FROM apps WHERE name = ?");
    $stmt->execute(array($app_data['name']));
    $app = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$app) {
        // Create a new app in the database
        $stmt = $db->prepare("INSERT INTO apps (name, enabled, token) VALUES (?, ?, ?)");
        $stmt->execute(array($app_data['name'], $app_data['enabled'], $app_data['token']));

        Flight::json(array('message' => 'App created'), 201);
    } else {
        // Update an existing app in the database
        $stmt = $db->prepare("UPDATE apps SET enabled = ?, token = ? WHERE name = ?");
        $stmt->execute(array($app_data['enabled'], $app_data['token'], $app_data['name']));

        Flight::json(array('message' => 'App updated'), 200);
    }
});

Flight::route('PUT /apps/@id', function ($id) {
    checkStaticBearerToken();

    // Get the request body
    $data = Flight::request()->data;

    // Validate the request body
    if (!isset($data->name) && !isset($data->enabled) && !isset($data->token)) {
        Flight::halt(400, 'Invalid request body');
    }

    // Update the app
    try {
        $db = Flight::db();
        $stmt = $db->prepare('UPDATE apps SET name = :name, enabled = :enabled, token = :token WHERE id = :id');
        $stmt->bindParam(':name', $data->name);
        $stmt->bindParam(':enabled', $data->enabled, PDO::PARAM_BOOL);
        $stmt->bindParam(':token', $data->token);
        $stmt->bindParam(':id', $id, PDO::PARAM_INT);
        $stmt->execute();

        // Check if the app was updated successfully
        if ($stmt->rowCount() === 0) {
            Flight::halt(404, 'App not found');
        }

        // Return the updated app
        $stmt = $db->prepare('SELECT * FROM apps WHERE id = :id');
        $stmt->bindParam(':id', $id, PDO::PARAM_INT);
        $stmt->execute();
        $app = $stmt->fetch(PDO::FETCH_ASSOC);

        Flight::json($app);
    } catch (PDOException $e) {
        Flight::halt(500, 'Internal server error');
    }
});

// API endpoints to list/read/upsert key-value pairs, which are stored in mysql database and owned by an "app"
Flight::route('GET /keys', function () {
    $app_id = checkAppBearerToken();

    // Retrieve all key-value pairs owned by the app from the database
    try {
        $db = Flight::db();
        $stmt = $db->prepare('SELECT * FROM kv WHERE app_id = :id');
        $stmt->bindParam(':id', $app_id, PDO::PARAM_STR);
        $stmt->execute();
        $kvPairs = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Return the key-value pairs as a JSON response
        Flight::json($kvPairs);
    } catch (PDOException $e) {
        Flight::halt(500, 'Internal server error');
    }
});

// API endpoint to get value of provided key, owned by an "app"
Flight::route('GET /key/@key', function ($key) {
    $app_id = checkAppBearerToken();

    // Retrieve the value of the specified key owned by the app from the database
    try {
        $db = Flight::db();
        $stmt = $db->prepare('SELECT value FROM kv WHERE app_id = :id AND key_name = :key');
        $stmt->bindParam(':id', $app_id, PDO::PARAM_INT);
        $stmt->bindParam(':key', $key, PDO::PARAM_STR);
        $stmt->execute();
        $value = $stmt->fetchColumn();

        // Check if the key exists and return the value as a JSON response
        if ($value !== false) {
            Flight::json(['value' => $value]);
        } else {
            // Return default value from querystring, if provided
            $default = Flight::request()->query->default;
            if ($default !== null) {
                Flight::json(['value' => $default]);
            } else {
                Flight::halt(404, 'Key not found');
            }
        }
    } catch (PDOException $e) {
        Flight::halt(500, 'Internal server error');
    }
});

// API endpoint to set value of provided key, owned by an "app"
Flight::route('POST /key/@action', function ($action = "store") {
    $app_id = checkAppBearerToken();

    // Get the request body, conver flight request to json object
    $data = json_decode(json_encode(Flight::request()->data));

    // Validate the request body
    if (!isset($data->key)) {
        Flight::halt(400, 'Invalid request body, must contain key');
    }

    // Validate the request body
    if (!isset($data->value)) {
        $data->value = "";
    }

    switch ($action) {
        case 'store':
            // Upsert the key-value pair
            try {
                $db = Flight::db();
                $stmt = $db->prepare('INSERT INTO kv (app_id, key_name, value) VALUES (:app_id, :key_name, :value) ON DUPLICATE KEY UPDATE value = VALUES(value)');
                $stmt->bindParam(':app_id', $app_id, PDO::PARAM_INT);
                $stmt->bindParam(':key_name', $data->key, PDO::PARAM_STR);
                $stmt->bindParam(':value', $data->value, PDO::PARAM_STR);
                $stmt->execute();
            } catch (PDOException $e) {
                Flight::halt(500, 'Internal server error');
            }
            break;
        case 'increment':
            // Increment the value of the specified key owned by the app in the database
            try {
                $db = Flight::db();
                $stmt = $db->prepare('UPDATE kv SET value = value + 1 WHERE app_id = :app_id AND key_name = :key_name');
                $stmt->bindParam(':app_id', $app_id, PDO::PARAM_INT);
                $stmt->bindParam(':key_name', $data->key, PDO::PARAM_STR);
                $stmt->execute();

                // If the key does not exist, create new key with value of 0
                if ($stmt->rowCount() === 0) {
                    $stmt = $db->prepare('INSERT INTO kv (app_id, key_name, value) VALUES (:app_id, :key_name, 1)');
                    $stmt->bindParam(':app_id', $app_id, PDO::PARAM_INT);
                    $stmt->bindParam(':key_name', $data->key, PDO::PARAM_STR);
                    $stmt->execute();
                }
            } catch (PDOException $e) {
                Flight::halt(500, 'Internal server error');
            }
            break;
        case 'decrement':
            // Decrement the value of the specified key owned by the app in the database
            try {
                $db = Flight::db();
                $stmt = $db->prepare('UPDATE kv SET value = value - 1 WHERE app_id = :app_id AND key_name = :key_name');
                $stmt->bindParam(':app_id', $app_id, PDO::PARAM_INT);
                $stmt->bindParam(':key_name', $data->key, PDO::PARAM_STR);
                $stmt->execute();

                // If the key does not exist, create new key with value of 0
                if ($stmt->rowCount() === 0) {
                    $stmt = $db->prepare('INSERT INTO kv (app_id, key_name, value) VALUES (:app_id, :key_name, -1)');
                    $stmt->bindParam(':app_id', $app_id, PDO::PARAM_INT);
                    $stmt->bindParam(':key_name', $data->key, PDO::PARAM_STR);
                    $stmt->execute();
                }
            } catch (PDOException $e) {
                error_log($e->getMessage());
                Flight::halt(500, 'Internal server error');
            }
            break;
    }

    // Return the updated key-value pair
    $stmt = $db->prepare('SELECT * FROM kv WHERE app_id = :app_id AND key_name = :key_name');
    $stmt->bindParam(':app_id', $app_id, PDO::PARAM_INT);
    $stmt->bindParam(':key_name', $data->key);
    $stmt->execute();
    $kvPair = $stmt->fetch(PDO::FETCH_ASSOC);
    Flight::json($kvPair);
    
});

// Run Flight
Flight::start();
