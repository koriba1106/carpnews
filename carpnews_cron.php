<?php
declare(strict_types=1);

/**
 * ==============================================================================
 * 広島東洋カープ ニュース自動収集パイプライン (極限堅牢・高精度クラスタリング版)
 * ==============================================================================
 *
 * 【正確性・堅牢性・セキュリティ機構】
 * 1. CLI実行強制・排他ロック(flock)・アトミックファイル置換(rename)
 * 2. 指数バックオフ付きcURLリトライ・TLS1.2以上強制・ストリームサイズ上限(2MB)
 * 3. LIBXML_NONET による XXE (XML外部エンティティ攻撃) 完全遮断
 * 4. SSRF対策 (プライベートIP・予約済みアドレス・不正スキームの厳格排除)
 * 5. NFKC文字正規化 + Bi-gram(2-gram) Dice係数による高精度な類似記事クラスタリング
 *    (表題や提供元が微妙に違う同一内容のニュースを正確に検知し、最大2件までに制限)
 * ==============================================================================
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit('Forbidden: CLI execution only.');
}

mb_internal_encoding('UTF-8');
mb_regex_encoding('UTF-8');

// ------------------------------------------------------------------------------
// 1. システム設定
// ------------------------------------------------------------------------------
$CONFIG = [
    'data_file'              => __DIR__ . '/data/news.json',
    'lock_file'              => __DIR__ . '/data/cron.lock',
    'max_items'              => 100,
    'max_per_topic_cluster'  => 2,      // 同一・類似内容のニュースは最大2件まで許可
    'similarity_threshold'   => 0.48,   // Bi-gram Dice係数の類似判定しきい値 (0.0〜1.0)
    'cluster_time_window_sec'=> 129600, // 類似判定を行う時間窓 (36時間以内の記事同士を比較)
    'max_xml_bytes'          => 2 * 1024 * 1024,
    'user_agent'             => 'Mozilla/5.0 (compatible; CarpNewsAggregator/5.0)',
    'timeout_sec'            => 15,
    'connect_timeout'        => 6,
    'max_retries'            => 3,
    // Google Newsの検索制限に引っかからないよう、メインとサブの2系統で網羅的に取得
    'search_queries' => [
        '("広島東洋カープ" OR "広島カープ" OR "カープ" OR "CARP" OR "赤ヘル" OR "マツダスタジアム" OR "ズムスタ") -鯉釣り -養殖 -錦鯉 -登山 -遭難 -競馬 -競輪 -ボートレース when:14d',
        '("新井監督" OR "新井貴浩" OR "広島・新井" OR "カープ女子" OR "由宇練習場" OR "大瀬良大地" OR "森下暢仁" OR "栗林良吏" OR "坂倉将吾" OR "小園海斗" OR "秋山翔吾" OR "菊池涼介") -鯉釣り -錦鯉 -登山 when:14d'
    ]
];

// ------------------------------------------------------------------------------
// 2. 解析マスターデータ（監督・コーチ・所属選手・用語辞書）
// ------------------------------------------------------------------------------
const PLAYER_DICTIONARY = [
    // 首脳陣
    '新井貴浩'   => ['新井監督', '新井貴浩', '新井貴', '新井さん'],
    '藤井彰人'   => ['藤井ヘッド', '藤井彰人'],
    '高信二'     => ['高監督', '高信二', '高二軍監督', '高2軍監督'],
    '石原慶幸'   => ['石原慶幸', '石原コーチ'],
    '赤松真人'   => ['赤松真人', '赤松コーチ'],
    '小窪哲也'   => ['小窪哲也', '小窪コーチ'],
    '野村祐輔'   => ['野村祐輔', '野村コーチ'],
    '菊地原毅'   => ['菊地原毅', '菊地原コーチ'],
    '永川勝浩'   => ['永川勝浩', '永川コーチ'],
    '廣瀬純'     => ['廣瀬純', '広瀬純', '廣瀬コーチ', '広瀬コーチ'],
    '迎祐一郎'   => ['迎祐一郎', '迎コーチ'],
    '東出輝裕'   => ['東出輝裕', '東出コーチ'],
    '朝山東洋'   => ['朝山東洋', '朝山コーチ'],
    '倉義和'     => ['倉義和', '倉コーチ'],

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
    '常廣羽也斗' => ['常廣羽也斗', '常広羽也斗', '常廣', '常広'],
    '齊藤汰直'   => ['齊藤汰直', '斉藤汰直'],
    '滝田一希'   => ['滝田一希', '滝田'],
    '益田武尚'   => ['益田武尚'],
    '河野佳'     => ['河野佳'],
    '遠藤淳志'   => ['遠藤淳志'],
    '塹江敦哉'   => ['塹江敦哉', '塹江'],
    'ケムナ誠'   => ['ケムナ誠', 'ケムナ'],
    '高橋昂也'   => ['高橋昂也', '髙橋昂也'],
    '森翔平'     => ['森翔平'],
    '松本竜也'   => ['松本竜也'],
    '大道温貴'   => ['大道温貴'],
    '鈴木健矢'   => ['鈴木健矢'],
    'ハーン'     => ['ハーン'],
    'ドミンゲス' => ['ドミンゲス'],

    // 捕手
    '坂倉将吾'   => ['坂倉将吾', '坂倉'],
    '會澤翼'     => ['會澤翼', '会沢翼', '會澤', '会沢'],
    '石原貴規'   => ['石原貴規'],
    '持丸泰輝'   => ['持丸泰輝', '持丸'],
    '高木翔斗'   => ['高木翔斗'],
    '清水叶人'   => ['清水叶人'],

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
    '韮澤雄也'   => ['韮澤雄也', '韮沢雄也', '韮澤', '韮沢'],
    '羽月隆太郎' => ['羽月隆太郎', '羽月'],
    '佐藤啓介'   => ['佐藤啓介'],
    'モンテロ'   => ['モンテロ'],
    'ファビアン' => ['ファビアン'],

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
    ['label' => '試合・戦評',             'regex' => '/(?:勝利|敗戦|引き分け|サヨナラ|完封|完投|本塁打|ホームラン|満塁弾|適時打|タイムリー|先発|登板|打線|連勝|連敗|得点|失点|逆転|白星|黒星|勝ち越し|スタメン|ヒーロー)/u'],
    ['label' => '公示・登録抹消',         'regex' => '/(?:公示|出場選手登録|登録抹消|一軍昇格|1軍昇格|二軍降格|2軍降格|再調整|一軍合流|1軍合流|復帰)/u'],
    ['label' => '怪我・コンディショニング', 'regex' => '/(?:負傷|怪我|けが|離脱|手術|リハビリ|違和感|検査|骨折|肉離れ|張り|コンディション)/u'],
    ['label' => 'ドラフト・新戦力',       'regex' => '/(?:ドラフト|新入団|新外国人|助っ人|獲得|指名|入団会見|ルーキー|新人|現役ドラフト|トライアウト|育成指名)/u'],
    ['label' => '契約・編成',             'regex' => '/(?:契約更改|年俸|FA|フリーエージェント|トレード|戦力外|育成契約|支配下登録|支配下|引退|退団|背番号|ポスティング)/u'],
    ['label' => 'キャンプ・練習',         'regex' => '/(?:キャンプ|紅白戦|オープン戦|ブルペン|シート打撃|フリー打撃|自主トレ|練習試合|日南|沖縄|秋季練習)/u'],
    ['label' => '球団・イベント',         'regex' => '/(?:マツダスタジアム|ズムスタ|グッズ|イベント|ファン感謝|始球式|観客動員|チケット|コラボ|カープ女子)/u']
];

const TEAM_LEVEL_DEFINITIONS = [
    '二軍・ファーム' => '/(?:二軍|2軍|ファーム|ウエスタン|由宇|大野寮|育成|教育リーグ)/u',
    '一軍'           => '/(?:一軍|1軍|セ・リーグ|クライマックス|CS|日本シリーズ|交流戦|開幕|首位|Aクラス)/u'
];

// 無関係なトピックを確実に弾く除外パターン
const EXCLUDE_PATTERN = '/(?:錦鯉|コイヘルペス|釣り堀|鯉釣り|登山|遭難|滑落|競輪|ボートレース|パチンコ|スロット)/u';
// 記事内に最低1つ必要な関連語（大文字小文字を区別しない `i` フラグ付与）
const REQUIRE_PATTERN = '/(?:広島|カープ|CARP|赤ヘル|新井|マツダ|ズムスタ|由宇|セ・リーグ|NPB|プロ野球)/ui';

// ------------------------------------------------------------------------------
// 3. テキスト正規化・解析・類似度クラスタリングクラス
// ------------------------------------------------------------------------------
final class CarpNewsParser
{
    /**
     * 文字列のサニタイズとNFKC正規化（全角英数を半角、半角カナを全角に統一）
     */
    public static function sanitizeAndNormalize(string $input): string
    {
        $clean = function_exists('mb_scrub')
            ? mb_scrub($input, 'UTF-8')
            : mb_convert_encoding($input, 'UTF-8', 'UTF-8');

        $clean = html_entity_decode(strip_tags($clean), ENT_QUOTES | ENT_HTML5, 'UTF-8');

        // 全角英数字・スペースを半角へ、半角カタカナを全角カタカナへ統一
        if (class_exists('Normalizer')) {
            $norm = Normalizer::normalize($clean, Normalizer::FORM_KC);
            if (is_string($norm)) {
                $clean = $norm;
            }
        } else {
            $clean = mb_convert_kana($clean, 'KVas', 'UTF-8');
        }

        // 制御文字をスペースに置換し、連続空白を圧縮
        $clean = preg_replace('/[\p{C}]+/u', ' ', $clean) ?? '';
        return trim(preg_replace('/\s+/u', ' ', $clean) ?? '');
    }

    /**
     * SSRF対策を含む厳格なURL検証
     */
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
        $parts = parse_url($filtered);
        if (!is_array($parts) || empty($parts['scheme']) || empty($parts['host'])) {
            return null;
        }
        $scheme = strtolower($parts['scheme']);
        if (!in_array($scheme, ['http', 'https'], true)) {
            return null;
        }
        $host = strtolower($parts['host']);
        if ($host === 'localhost' || str_ends_with($host, '.local') || str_ends_with($host, '.internal')) {
            return null;
        }
        // IPアドレス直接指定の場合はプライベートIP・予約済み範囲を拒否
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
                return null;
            }
        }
        return $filtered;
    }

    /**
     * タイトルから末尾のメディア名表記を綺麗に除去する
     */
    public static function cleanTitle(string $rawTitle): string
    {
        $clean = self::sanitizeAndNormalize($rawTitle);
        // 末尾の「 - メディア名」「 | メディア名」等を除去
        $clean = preg_replace('/\s+[-–—―|｜丨]\s+[^-–—―|｜丨]+$/u', '', $clean) ?? $clean;
        return trim($clean);
    }

    public static function extractTeamLevel(string $text): string
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
                if (mb_stripos($text, $alias) !== false) {
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

    /**
     * 類似度判定のために、タイトルから定型ブラケット（【広島】等）や記号・助詞を取り除き、
     * ユニークな Bi-gram (2文字ずつのトークン配列) を生成する
     *
     * @return list<string>
     */
    public static function buildBigrams(string $title): array
    {
        $norm = mb_strtolower(self::sanitizeAndNormalize($title), 'UTF-8');

        // 先頭や文中の【広島】【カープ】＜野球＞（デイリー）などの定型ラベルを除去
        $norm = preg_replace('/[\[【<＜(（][^\]】>＞)）]{1,15}[\]】>＞)）]/u', '', $norm) ?? $norm;
        // 共通頻出語（「広島東洋カープ」「広島カープ」「カープ」「広島」単体）の重みを下げるため除去
        $norm = preg_replace('/(?:広島東洋カープ|広島カープ|広島|カープ|carp|プロ野球)/ui', '', $norm) ?? $norm;
        // 句読点・記号・空白をすべて除去（Unicodeプロパティ使用）
        $norm = preg_replace('/[\p{P}\p{S}\p{Z}\p{C}]+/u', '', $norm) ?? $norm;

        $len = mb_strlen($norm, 'UTF-8');
        if ($len === 0) {
            return [];
        }
        if ($len === 1) {
            return [$norm];
        }

        $bigrams = [];
        for ($i = 0; $i < $len - 1; $i++) {
            $bg = mb_substr($norm, $i, 2, 'UTF-8');
            $bigrams[$bg] = true;
        }
        return array_keys($bigrams);
    }

    /**
     * 2つの Bi-gram 集合間の Dice 係数 (0.0 〜 1.0) を算出する
     *
     * @param list<string> $bgA
     * @param list<string> $bgB
     */
    public static function calculateDiceSimilarity(array $bgA, array $bgB): float
    {
        $countA = count($bgA);
        $countB = count($bgB);
        if ($countA === 0 || $countB === 0) {
            return 0.0;
        }

        $setB = array_flip($bgB);
        $intersection = 0;
        foreach ($bgA as $token) {
            if (isset($setB[$token])) {
                $intersection++;
            }
        }

        return (2.0 * $intersection) / ($countA + $countB);
    }

    /**
     * 2つの記事が「同一・類似トピック」かどうかを総合判定する
     *
     * @param array<string, mixed> $itemA
     * @param list<string>         $bgA
     * @param array<string, mixed> $itemB
     * @param list<string>         $bgB
     */
    public static function isSimilarArticle(
        array $itemA,
        array $bgA,
        array $itemB,
        array $bgB,
        float $threshold,
        int $timeWindowSec
    ): bool {
        // 投稿日時が時間窓（例：36時間）以上離れている場合は別ニュースとして扱う
        $timeA = strtotime((string)($itemA['pubDate'] ?? '')) ?: 0;
        $timeB = strtotime((string)($itemB['pubDate'] ?? '')) ?: 0;
        if ($timeA > 0 && $timeB > 0 && abs($timeA - $timeB) > $timeWindowSec) {
            return false;
        }

        $dice = self::calculateDiceSimilarity($bgA, $bgB);

        // 登場している選手名が共通しているかチェック
        $playersA = is_array($itemA['players'] ?? null) ? $itemA['players'] : [];
        $playersB = is_array($itemB['players'] ?? null) ? $itemB['players'] : [];
        $sharedPlayers = array_intersect($playersA, $playersB);

        // 同じ選手について言及しており、かつカテゴリも一致している場合は類似判定のしきい値を緩和（より厳しく重複検知）
        if (!empty($sharedPlayers)) {
            $catsA = is_array($itemA['categories'] ?? null) ? $itemA['categories'] : [];
            $catsB = is_array($itemB['categories'] ?? null) ? $itemB['categories'] : [];
            if (!empty(array_intersect($catsA, $catsB))) {
                $threshold -= 0.12;
            } else {
                $threshold -= 0.06;
            }
        }

        return $dice >= $threshold;
    }

    /**
     * 類似ニュースをクラスタリングし、1つの話題につき最大 $maxPerCluster 件（2件）までに制限する
     *
     * @param list<array<string, mixed>> $sortedItems 最新順にソート済みの記事配列
     * @return list<array<string, mixed>>
     */
    public static function filterSimilarClusters(
        array $sortedItems,
        int $maxPerCluster,
        float $threshold,
        int $timeWindowSec
    ): array {
        /** @var list<array{repItem: array<string, mixed>, repBigrams: list<string>, count: int}> $clusters */
        $clusters = [];
        $result = [];

        foreach ($sortedItems as $item) {
            $title = (string)($item['title'] ?? '');
            $bigrams = self::buildBigrams($title);

            $matchedClusterIndex = null;
            foreach ($clusters as $idx => $cluster) {
                if (self::isSimilarArticle(
                    $item,
                    $bigrams,
                    $cluster['repItem'],
                    $cluster['repBigrams'],
                    $threshold,
                    $timeWindowSec
                )) {
                    $matchedClusterIndex = $idx;
                    break;
                }
            }

            if ($matchedClusterIndex === null) {
                // 新規トピックとして登録
                $clusters[] = [
                    'repItem'    => $item,
                    'repBigrams' => $bigrams,
                    'count'      => 1
                ];
                $result[] = $item;
            } else {
                // 既存トピックと類似している場合、上限（2件）未満なら採用、上限以上ならスキップ
                if ($clusters[$matchedClusterIndex]['count'] < $maxPerCluster) {
                    $clusters[$matchedClusterIndex]['count']++;
                    $result[] = $item;
                }
            }
        }

        return $result;
    }
}

// ------------------------------------------------------------------------------
// 4. 指数バックオフ付き・高耐久RSSフェッチャー
// ------------------------------------------------------------------------------
function fetchRssWithRetry(string $url, array $config): string
{
    $maxRetries = (int)$config['max_retries'];
    $maxBytes   = (int)$config['max_xml_bytes'];
    $lastError  = 'Unknown error';

    for ($attempt = 1; $attempt <= $maxRetries; $attempt++) {
        $ch = curl_init();
        if ($ch === false) {
            throw new RuntimeException('cURLの初期化に失敗しました。');
        }

        curl_setopt_array($ch, [
            CURLOPT_URL             => $url,
            CURLOPT_RETURNTRANSFER  => true,
            CURLOPT_TIMEOUT         => $config['timeout_sec'],
            CURLOPT_CONNECTTIMEOUT  => $config['connect_timeout'],
            CURLOPT_USERAGENT       => $config['user_agent'],
            CURLOPT_HTTPHEADER      => ['Accept: application/rss+xml, application/xml, text/xml;q=0.9, */*;q=0.1'],
            CURLOPT_ENCODING        => '', // gzip/deflate 自動展開
            CURLOPT_FOLLOWLOCATION  => true,
            CURLOPT_MAXREDIRS       => 3,
            CURLOPT_PROTOCOLS       => CURLPROTO_HTTPS | CURLPROTO_HTTP,
            CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS | CURLPROTO_HTTP,
            CURLOPT_SSL_VERIFYPEER  => true,
            CURLOPT_SSL_VERIFYHOST  => 2,
            CURLOPT_SSLVERSION      => CURL_SSLVERSION_TLSv1_2,
            CURLOPT_NOPROGRESS      => false,
            CURLOPT_PROGRESSFUNCTION => static function ($resource, int $dlTotal, int $dlNow) use ($maxBytes): int {
                return ($dlNow > $maxBytes || $dlTotal > $maxBytes) ? 1 : 0;
            }
        ]);

        $response = curl_exec($ch);
        $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlErr  = curl_error($ch);
        curl_close($ch);

        if ($httpCode === 200 && is_string($response) && $response !== '') {
            return $response;
        }

        $lastError = "HTTP {$httpCode} / cURL: {$curlErr}";
        if ($attempt < $maxRetries) {
            // 指数バックオフ (1秒, 2秒...)
            usleep($attempt * 1000000);
        }
    }

    throw new RuntimeException("RSS取得失敗 (全{$maxRetries}回試行): {$lastError}");
}

// ------------------------------------------------------------------------------
// 5. メイン処理
// ------------------------------------------------------------------------------
$lockFp = null;

try {
    $startTime = microtime(true);

    $dataDir = dirname($CONFIG['data_file']);
    if (!is_dir($dataDir) && !mkdir($dataDir, 0750, true) && !is_dir($dataDir)) {
        throw new RuntimeException("データディレクトリの作成に失敗しました: {$dataDir}");
    }

    $lockFp = fopen($CONFIG['lock_file'], 'c');
    if ($lockFp === false || !flock($lockFp, LOCK_EX | LOCK_NB)) {
        throw new RuntimeException('別プロセスが実行中のためスキップしました。');
    }

    // 既存データの安全な読み込み（深さ制限16・破損自動無視）
    $existingItems = [];
    if (is_file($CONFIG['data_file']) && is_readable($CONFIG['data_file'])) {
        $rawJson = file_get_contents($CONFIG['data_file']);
        if (is_string($rawJson) && $rawJson !== '') {
            $decoded = json_decode($rawJson, true, 16, JSON_INVALID_UTF8_IGNORE);
            if (is_array($decoded)) {
                $existingItems = $decoded;
            }
        }
    }

    // 複数クエリからRSSを取得・パース
    $newItems = [];
    foreach ($CONFIG['search_queries'] as $query) {
        $rssUrl = 'https://news.google.com/rss/search?q=' . rawurlencode($query) . '&hl=ja&gl=JP&ceid=JP:ja';
        $xmlData = fetchRssWithRetry($rssUrl, $CONFIG);

        $prevUseErrors = libxml_use_internal_errors(true);
        $xml = simplexml_load_string($xmlData, SimpleXMLElement::class, LIBXML_NOCDATA | LIBXML_NONET | LIBXML_NOBLANKS);
        libxml_clear_errors();
        libxml_use_internal_errors($prevUseErrors);

        if ($xml === false || !isset($xml->channel->item)) {
            continue;
        }

        foreach ($xml->channel->item as $item) {
            $rawTitle = CarpNewsParser::sanitizeAndNormalize((string)($item->title ?? ''));
            if ($rawTitle === '' || preg_match(EXCLUDE_PATTERN, $rawTitle) === 1) {
                continue;
            }

            $players = CarpNewsParser::extractPlayers($rawTitle);
            if (preg_match(REQUIRE_PATTERN, $rawTitle) !== 1 && empty($players)) {
                continue;
            }

            $validLink = CarpNewsParser::validateUrl((string)($item->link ?? ''));
            if ($validLink === null) {
                continue;
            }

            $rawPubDate = (string)($item->pubDate ?? '');
            $timestamp = $rawPubDate !== '' ? strtotime($rawPubDate) : false;
            if ($timestamp === false || $timestamp > time() + 300) {
                $timestamp = time();
            }

            $source = CarpNewsParser::sanitizeAndNormalize((string)($item->source ?? 'Google News'));
            if ($source === '') {
                $source = 'Google News';
            }

            $newItems[] = [
                'id'         => substr(hash('sha256', $validLink), 0, 16),
                'title'      => CarpNewsParser::cleanTitle($rawTitle),
                'rawTitle'   => $rawTitle,
                'link'       => $validLink,
                'pubDate'    => date('c', $timestamp),
                'source'     => $source,
                'teamLevel'  => CarpNewsParser::extractTeamLevel($rawTitle),
                'players'    => $players,
                'categories' => CarpNewsParser::extractCategories($rawTitle)
            ];
        }
    }

    // URL単位での完全重複排除＆再正規化マージ
    $store = [];
    foreach (array_merge($newItems, $existingItems) as $item) {
        if (!is_array($item)) {
            continue;
        }
        $link = CarpNewsParser::validateUrl((string)($item['link'] ?? ''));
        if ($link === null || isset($store[$link])) {
            continue;
        }

        $checkTitle = CarpNewsParser::sanitizeAndNormalize((string)($item['rawTitle'] ?? $item['title'] ?? ''));
        if ($checkTitle === '' || preg_match(EXCLUDE_PATTERN, $checkTitle) === 1) {
            continue;
        }

        $players = CarpNewsParser::extractPlayers($checkTitle);
        if (preg_match(REQUIRE_PATTERN, $checkTitle) !== 1 && empty($players)) {
            continue;
        }

        $cleanTitle = CarpNewsParser::cleanTitle($checkTitle);
        if ($cleanTitle === '') {
            continue;
        }

        $pubTimestamp = isset($item['pubDate']) ? strtotime((string)$item['pubDate']) : false;
        if ($pubTimestamp === false || $pubTimestamp > time() + 300) {
            $pubTimestamp = time();
        }

        // 14日より古い記事は自動パージ（データの鮮度維持）
        if ($pubTimestamp < time() - (14 * 86400)) {
            continue;
        }

        $source = CarpNewsParser::sanitizeAndNormalize((string)($item['source'] ?? 'Google News'));

        $store[$link] = [
            'id'         => substr(hash('sha256', $link), 0, 16),
            'title'      => $cleanTitle,
            'rawTitle'   => $checkTitle,
            'link'       => $link,
            'pubDate'    => date('c', $pubTimestamp),
            'source'     => $source !== '' ? $source : 'Google News',
            'teamLevel'  => CarpNewsParser::extractTeamLevel($checkTitle),
            'players'    => $players,
            'categories' => CarpNewsParser::extractCategories($checkTitle)
        ];
    }

    // 最新順にソート
    $dataset = array_values($store);
    usort($dataset, static function (array $a, array $b): int {
        return strtotime((string)$b['pubDate']) <=> strtotime((string)$a['pubDate']);
    });

    // Bi-gram Dice係数＋選手タグ照合による類似記事クラスタリング（同一話題は最大2件までに抑制）
    $dataset = CarpNewsParser::filterSimilarClusters(
        $dataset,
        (int)$CONFIG['max_per_topic_cluster'],
        (float)$CONFIG['similarity_threshold'],
        (int)$CONFIG['cluster_time_window_sec']
    );

    // 最大件数（100件）に切り詰め
    $dataset = array_slice($dataset, 0, (int)$CONFIG['max_items']);

    $jsonOutput = json_encode(
        $dataset,
        JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR
    );

    // 一時ファイルへ書き込み・検証後にアトミック置換
    $tempFile = $CONFIG['data_file'] . '.tmp.' . getmypid() . '.' . bin2hex(random_bytes(4));
    $writtenBytes = file_put_contents($tempFile, $jsonOutput, LOCK_EX);
    if ($writtenBytes === false || $writtenBytes !== strlen($jsonOutput)) {
        @unlink($tempFile);
        throw new RuntimeException('一時ファイルの完全書き込みに失敗しました。');
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
