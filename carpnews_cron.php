<?php
declare(strict_types=1);

/**
 * ==============================================================================
 * 広島東洋カープ 球団・監督・所属選手 ニュース自動収集パイプライン (堅牢・高セキュリティ版)
 * ==============================================================================
 *
 * 【セキュリティ・堅牢性対策】
 * - CLI実行強制 (Web経由での不正実行を遮断)
 * - flock() によるプロセス排他制御と一時ファイルからのアトミック置換
 * - LIBXML_NONET による XXE (XML外部エンティティ攻撃) 完全遮断
 * - cURL ストリームサイズ制限 (巨大レスポンスによるメモリ枯渇 DoS 防止)
 * - HTTP/HTTPS URLスキーム検証と UTF-8 不正バイト列・制御文字サニタイズ
 * ==============================================================================
 */

// Web経由での直接アクセスを遮断 (CLI または 明示的な内部実行のみ許可)
if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit('Forbidden: CLI execution only.');
}

mb_internal_encoding('UTF-8');

// ------------------------------------------------------------------------------
// 1. システム設定
// ------------------------------------------------------------------------------
$CONFIG = [
    'data_file'      => __DIR__ . '/data/news.json',
    'lock_file'      => __DIR__ . '/data/cron.lock',
    'max_items'      => 100,
    'max_xml_bytes'  => 2 * 1024 * 1024, // 最大2MB制限 (メモリ枯渇防止)
    'user_agent'     => 'CarpNewsAggregator/4.0 (+https://example.com; bot)',
    'timeout_sec'    => 12,
    'connect_timeout'=> 5,
    'search_queries' => [
        // カープ関連キーワード
        'include' => '("広島東洋カープ" OR "広島カープ" OR "カープ" OR "新井監督" OR "新井貴浩" OR "マツダスタジアム")',
        // 英語のコイ(carp)や無関係なトピックを除外
        'exclude' => '-鯉釣り -養殖 -錦鯉 -登山 -遭難',
        'period'  => 'when:14d'
    ]
];

// ------------------------------------------------------------------------------
// 2. 解析マスターデータ（監督・コーチ・主力および所属選手・分類定義）
// ------------------------------------------------------------------------------
const PLAYER_DICTIONARY = [
    // 首脳陣
    '新井貴浩' => ['新井監督', '新井貴浩', '新井貴'],
    '藤井彰人' => ['藤井ヘッド', '藤井彰人'],
    '高信二'   => ['高監督', '高信二', '高二軍監督'],
    '石原慶幸' => ['石原慶幸', '石原コーチ'],
    '赤松真人' => ['赤松真人', '赤松コーチ'],
    '小窪哲也' => ['小窪哲也', '小窪コーチ'],
    '野村祐輔' => ['野村祐輔', '野村コーチ'],

    // 投手
    '大瀬良大地' => ['大瀬良大地', '大瀬良'],
    '九里亜蓮'   => ['九里亜蓮', '九里'],
    '森下暢仁'   => ['森下暢仁', '森下'],
    '床田寛樹'   => ['床田寛樹', '床田'],
    '栗林良吏'   => ['栗林良吏', '栗林'],
    '島内颯太郎' => ['島内颯太郎', '島内'],
    '矢崎拓也'   => ['矢崎拓也', '矢崎'],
    '黒原拓未'   => ['黒原拓未', '黒原'],
    '森浦大輔'   => ['森浦大輔', '森浦'],
    'アドゥワ誠' => ['アドゥワ誠', 'アドゥワ'],
    '玉村昇悟'   => ['玉村昇悟', '玉村'],
    '常廣羽也斗' => ['常廣羽也斗', '常廣', '常広'],
    '齊藤汰直'   => ['齊藤汰直', '斉藤汰直'],
    '滝田一希'   => ['滝田一希', '滝田'],
    '益田武尚'   => ['益田武尚'],
    '河野佳'     => ['河野佳'],
    '遠藤淳志'   => ['遠藤淳志'],
    'ハーン'     => ['ハーン'],

    // 捕手
    '坂倉将吾'   => ['坂倉将吾', '坂倉'],
    '會澤翼'     => ['會澤翼', '会沢翼', '會澤', '会沢'],
    '石原貴規'   => ['石原貴規'],
    '持丸泰輝'   => ['持丸泰輝', '持丸'],
    '高木翔斗'   => ['高木翔斗'],

    // 内野手
    '菊池涼介'   => ['菊池涼介', '菊池'],
    '小園海斗'   => ['小園海斗', '小園'],
    '堂林翔太'   => ['堂林翔太', '堂林'],
    '矢野雅哉'   => ['矢野雅哉', '矢野'],
    '田中広輔'   => ['田中広輔'],
    '松山竜平'   => ['松山竜平', '松山'],
    '林晃汰'     => ['林晃汰'],
    '二俣翔一'   => ['二俣翔一', '二俣'],
    '仲田侑仁'   => ['仲田侑仁'],
    '内田湘大'   => ['内田湘大'],
    '佐々木泰'   => ['佐々木泰'],
    '勝田成'     => ['勝田成'],

    // 外野手
    '秋山翔吾'   => ['秋山翔吾', '秋山'],
    '野間峻祥'   => ['野間峻祥', '野間'],
    '末包昇大'   => ['末包昇大', '末包'],
    '田村俊介'   => ['田村俊介'],
    '宇草孔基'   => ['宇草孔基', '宇草'],
    '大盛穂'     => ['大盛穂', '大盛'],
    '中村奨成'   => ['中村奨成'],
    '中村健人'   => ['中村健人'],
    '中村貴浩'   => ['中村貴浩'],
    '久保修'     => ['久保修'],
    '平川蓮'     => ['平川蓮'],
    '名原典彦'   => ['名原典彦']
];

const CATEGORY_DEFINITIONS = [
    ['label' => '試合・戦評',       'regex' => '/(?:勝利|敗戦|引き分け|サヨナラ|完封|完投|本塁打|ホームラン|適時打|タイムリー|先発|登板|打線|連勝|連敗|得点|失点|逆転|白星|黒星)/u'],
    ['label' => '公示・登録抹消',   'regex' => '/(?:公示|出場選手登録|登録抹消|一軍昇格|1軍昇格|二軍降格|2軍降格|再調整|復帰)/u'],
    ['label' => '怪我・コンディショニング', 'regex' => '/(?:負傷|怪我|けが|離脱|手術|リハビリ|抹消|違和感|検査|骨折|肉離れ)/u'],
    ['label' => 'ドラフト・新戦力', 'regex' => '/(?:ドラフト|新入団|新外国人|助っ人|獲得|指名|入団会見|ルーキー|新人|現役ドラフト|トライアウト)/u'],
    ['label' => '契約・編成',       'regex' => '/(?:契約更改|年俸|FA|フリーエージェント|トレード|戦力外|育成契約|支配下登録|引退|退団|背番号)/u'],
    ['label' => 'キャンプ・練習',   'regex' => '/(?:キャンプ|紅白戦|オープン戦|ブルペン|シート打撃|フリー打撃|自主トレ|練習試合|日南|沖縄)/u'],
    ['label' => '球団・イベント',   'regex' => '/(?:マツダスタジアム|グッズ|イベント|ファン感謝|始球式|観客動員|チケット|コラボ)/u']
];

const TEAM_LEVEL_DEFINITIONS = [
    '二軍・ファーム' => '/(?:二軍|2軍|ファーム|ウエスタン|由宇|大野寮|育成)/u',
    '一軍'           => '/(?:一軍|1軍|セ・リーグ|クライマックス|CS|日本シリーズ|交流戦|開幕)/u'
];

// カープと無関係な記事を弾く除外パターン
const EXCLUDE_PATTERN = '/(?:錦鯉|コイヘルペス|釣り堀|登山|遭難|滑落)/u';
// 記事内に最低1つは含まれるべき関連語（ノイズ混入防止）
const REQUIRE_PATTERN = '/(?:広島|カープ|新井|マツダ|由宇|セ・リーグ|NPB|プロ野球)/u';

// ------------------------------------------------------------------------------
// 3. テキスト解析＆サニタイズクラス
// ------------------------------------------------------------------------------
final class CarpNewsParser
{
    public static function sanitizeText(string $input): string
    {
        // 不正なUTF-8バイト列を除去
        $clean = function_exists('mb_scrub')
            ? mb_scrub($input, 'UTF-8')
            : mb_convert_encoding($input, 'UTF-8', 'UTF-8');

        // 制御文字（改行・タブ含む）をスペースに置換し、HTMLタグを除去
        $clean = strip_tags($clean);
        $clean = preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $clean) ?? '';
        return trim(preg_replace('/\s+/u', ' ', $clean) ?? '');
    }

    public static function validateUrl(string $url): ?string
    {
        $url = trim($url);
        if ($url === '' || strlen($url) > 2048) {
            return null;
        }
        $filtered = filter_var($url, FILTER_VALIDATE_URL);
        if ($filtered === false) {
            return null;
        }
        $scheme = strtolower((string)parse_url($filtered, PHP_URL_SCHEME));
        if (!in_array($scheme, ['http', 'https'], true)) {
            return null;
        }
        return $filtered;
    }

    public static function cleanTitle(string $rawTitle): string
    {
        $clean = self::sanitizeText($rawTitle);
        // 末尾の「 - メディア名」や先頭の「【広島】」等を整形
        $clean = preg_replace('/\s*[-–|丨]\s*[^-–|丨]+$/u', '', $clean) ?? $clean;
        return trim($clean);
    }

    public static function extractTeamLevel(string $text): ?string
    {
        foreach (TEAM_LEVEL_DEFINITIONS as $label => $regex) {
            if (preg_match($regex, $text) === 1) {
                return $label;
            }
        }
        return '球団全般';
    }

    /**
     * @return list<string>
     */
    public static function extractPlayers(string $text): array
    {
        $found = [];
        foreach (PLAYER_DICTIONARY as $canonicalName => $aliases) {
            foreach ($aliases as $alias) {
                if (mb_strpos($text, $alias) !== false) {
                    $found[] = $canonicalName;
                    break;
                }
            }
        }
        return array_values(array_unique($found));
    }

    /**
     * @return list<string>
     */
    public static function extractCategories(string $text): array
    {
        $categories = [];
        foreach (CATEGORY_DEFINITIONS as $def) {
            if (preg_match($def['regex'], $text) === 1) {
                $categories[] = $def['label'];
            }
        }
        if (empty($categories)) {
            $categories[] = '球団・選手話題';
        }
        return $categories;
    }
}

// ------------------------------------------------------------------------------
// 4. メイン処理（排他制御・RSSフェッチ・検証・アトミック保存）
// ------------------------------------------------------------------------------
$lockFp = null;

try {
    $startTime = microtime(true);

    $dataDir = dirname($CONFIG['data_file']);
    if (!is_dir($dataDir) && !mkdir($dataDir, 0750, true) && !is_dir($dataDir)) {
        throw new RuntimeException("データディレクトリの作成に失敗しました: {$dataDir}");
    }

    // 排他ロック取得（CRONの多重起動による競合を防止）
    $lockFp = fopen($CONFIG['lock_file'], 'c');
    if ($lockFp === false || !flock($lockFp, LOCK_EX | LOCK_NB)) {
        throw new RuntimeException('別プロセスが実行中のためスキップしました。');
    }

    $queryString = implode(' ', [
        $CONFIG['search_queries']['include'],
        $CONFIG['search_queries']['exclude'],
        $CONFIG['search_queries']['period']
    ]);
    $rssUrl = 'https://news.google.com/rss/search?q=' . rawurlencode($queryString) . '&hl=ja&gl=JP&ceid=JP:ja';

    $ch = curl_init();
    if ($ch === false) {
        throw new RuntimeException('cURLの初期化に失敗しました。');
    }

    $maxBytes = $CONFIG['max_xml_bytes'];
    $receivedBytes = 0;

    curl_setopt_array($ch, [
        CURLOPT_URL            => $rssUrl,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => $CONFIG['timeout_sec'],
        CURLOPT_CONNECTTIMEOUT => $CONFIG['connect_timeout'],
        CURLOPT_USERAGENT      => $CONFIG['user_agent'],
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS      => 3,
        CURLOPT_PROTOCOLS      => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        CURLOPT_REDIR_PROTOCOLS=> CURLPROTO_HTTP | CURLPROTO_HTTPS,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        // 巨大レスポンスによるメモリ枯渇防止
        CURLOPT_NOPROGRESS     => false,
        CURLOPT_PROGRESSFUNCTION => static function ($resource, int $dlTotal, int $dlNow) use ($maxBytes): int {
            return ($dlNow > $maxBytes || $dlTotal > $maxBytes) ? 1 : 0;
        }
    ]);

    $xmlData = curl_exec($ch);
    $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlErr = curl_error($ch);
    curl_close($ch);

    if ($httpCode !== 200 || !is_string($xmlData) || $xmlData === '') {
        throw new RuntimeException("RSS取得失敗 (HTTP Code: {$httpCode}, Error: {$curlErr})");
    }

    // XXE攻撃対策: LIBXML_NONET を指定して外部エンティティ通信を完全遮断
    $prevUseErrors = libxml_use_internal_errors(true);
    $xml = simplexml_load_string($xmlData, SimpleXMLElement::class, LIBXML_NOCDATA | LIBXML_NONET | LIBXML_NOBLANKS);
    libxml_clear_errors();
    libxml_use_internal_errors($prevUseErrors);

    if ($xml === false) {
        throw new RuntimeException('XMLパースに失敗しました。');
    }

    // 既存データの安全な読み込み
    $existingItems = [];
    if (is_file($CONFIG['data_file']) && is_readable($CONFIG['data_file'])) {
        $rawJson = file_get_contents($CONFIG['data_file']);
        if (is_string($rawJson) && $rawJson !== '') {
            $decoded = json_decode($rawJson, true);
            if (is_array($decoded)) {
                $existingItems = $decoded;
            }
        }
    }

    // 新規記事のパース
    $newItems = [];
    if (isset($xml->channel->item)) {
        foreach ($xml->channel->item as $item) {
            $rawTitle = CarpNewsParser::sanitizeText((string)($item->title ?? ''));
            if ($rawTitle === '') {
                continue;
            }
            if (preg_match(EXCLUDE_PATTERN, $rawTitle) === 1) {
                continue;
            }
            if (preg_match(REQUIRE_PATTERN, $rawTitle) !== 1 && empty(CarpNewsParser::extractPlayers($rawTitle))) {
                continue;
            }

            $validLink = CarpNewsParser::validateUrl((string)($item->link ?? ''));
            if ($validLink === null) {
                continue;
            }

            $rawPubDate = (string)($item->pubDate ?? '');
            $timestamp = $rawPubDate !== '' ? strtotime($rawPubDate) : false;
            // 未来の日時や不正な日時は現在時刻に補正
            if ($timestamp === false || $timestamp > time() + 300) {
                $timestamp = time();
            }
            $pubDate = date('c', $timestamp);

            $source = CarpNewsParser::sanitizeText((string)($item->source ?? 'Google News'));
            if ($source === '') {
                $source = 'Google News';
            }

            $newItems[] = [
                'id'         => substr(hash('sha256', $validLink), 0, 16),
                'title'      => CarpNewsParser::cleanTitle($rawTitle),
                'rawTitle'   => $rawTitle,
                'link'       => $validLink,
                'pubDate'    => $pubDate,
                'source'     => $source,
                'teamLevel'  => CarpNewsParser::extractTeamLevel($rawTitle),
                'players'    => CarpNewsParser::extractPlayers($rawTitle),
                'categories' => CarpNewsParser::extractCategories($rawTitle)
            ];
        }
    }

    // 重複排除＆スキーマ再検証マージ
    $store = [];
    foreach (array_merge($newItems, $existingItems) as $item) {
        if (!is_array($item)) {
            continue;
        }
        $link = CarpNewsParser::validateUrl((string)($item['link'] ?? ''));
        if ($link === null || isset($store[$link])) {
            continue;
        }

        $checkTitle = (string)($item['rawTitle'] ?? $item['title'] ?? '');
        if ($checkTitle === '' || preg_match(EXCLUDE_PATTERN, $checkTitle) === 1) {
            continue;
        }

        // 既存データに対しても最新の選手・カテゴリ抽出ルールを適用して正規化
        $store[$link] = [
            'id'         => substr(hash('sha256', $link), 0, 16),
            'title'      => CarpNewsParser::cleanTitle($checkTitle),
            'rawTitle'   => CarpNewsParser::sanitizeText($checkTitle),
            'link'       => $link,
            'pubDate'    => isset($item['pubDate']) && strtotime((string)$item['pubDate']) !== false
                ? date('c', strtotime((string)$item['pubDate']))
                : date('c'),
            'source'     => CarpNewsParser::sanitizeText((string)($item['source'] ?? 'Google News')),
            'teamLevel'  => CarpNewsParser::extractTeamLevel($checkTitle),
            'players'    => CarpNewsParser::extractPlayers($checkTitle),
            'categories' => CarpNewsParser::extractCategories($checkTitle)
        ];
    }

    // 最新順にソートして最大件数で切り詰め
    $dataset = array_values($store);
    usort($dataset, static function (array $a, array $b): int {
        return strtotime($b['pubDate']) <=> strtotime($a['pubDate']);
    });
    $dataset = array_slice($dataset, 0, $CONFIG['max_items']);

    // JSONエンコード検証（失敗時は例外スロー）
    $jsonOutput = json_encode(
        $dataset,
        JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR
    );

    // 一時ファイルへ書き込み後、アトミックにリネーム（読み取り側の破損を完全防止）
    $tempFile = $CONFIG['data_file'] . '.tmp.' . getmypid();
    if (file_put_contents($tempFile, $jsonOutput, LOCK_EX) === false) {
        throw new RuntimeException('一時ファイルの書き込みに失敗しました。');
    }
    chmod($tempFile, 0644);

    if (!rename($tempFile, $CONFIG['data_file'])) {
        @unlink($tempFile);
        throw new RuntimeException('JSONファイルのアトミック置換に失敗しました。');
    }

    $elapsed = round(microtime(true) - $startTime, 3);
    echo '[' . date('Y-m-d H:i:s') . '] 正常終了: ' . count($dataset) . " 件のカープニュースを更新しました (処理時間: {$elapsed}秒)\n";

} catch (Throwable $e) {
    error_log('[CarpNewsCron Error] ' . $e->getMessage());
    fwrite(STDERR, '[' . date('Y-m-d H:i:s') . '] エラー: ' . $e->getMessage() . "\n");
    exit(1);
} finally {
    if (is_resource($lockFp)) {
        flock($lockFp, LOCK_UN);
        fclose($lockFp);
    }
}
