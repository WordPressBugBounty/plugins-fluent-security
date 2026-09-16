<?php

namespace FluentAuth\App\Services;

/**
 * A QR code encoder, producing SVG.
 *
 * This exists rather than a hosted image service because the only thing it is asked to
 * encode is a TOTP provisioning URI, and that URI contains the shared secret. Sending
 * it to a third party to be drawn would hand the second factor to whoever draws it -
 * and leave it in their logs. Nothing here leaves the server.
 *
 * Scope is deliberately narrow: byte mode, error correction level M, versions 1 to 16.
 * That reaches 450 bytes, far more than any otpauth:// URI, and every table below is
 * one a wider encoder would need several of. ISO/IEC 18004 is the reference.
 */
class QrCode
{
    /**
     * Per version: EC codewords per block, then each group as [blocks, data codewords
     * per block]. Level M throughout - roughly 15% of the symbol can be lost and still
     * read, which is the usual choice for something displayed on a screen.
     */
    private static $blockTable = [
        1  => [10, 1, 16, 0, 0],
        2  => [16, 1, 28, 0, 0],
        3  => [26, 1, 44, 0, 0],
        4  => [18, 2, 32, 0, 0],
        5  => [24, 2, 43, 0, 0],
        6  => [16, 4, 27, 0, 0],
        7  => [18, 4, 31, 0, 0],
        8  => [22, 2, 38, 2, 39],
        9  => [22, 3, 36, 2, 37],
        10 => [26, 4, 43, 1, 44],
        11 => [30, 1, 50, 4, 51],
        12 => [22, 6, 36, 2, 37],
        13 => [22, 8, 37, 1, 38],
        14 => [24, 4, 40, 5, 41],
        15 => [24, 5, 41, 5, 42],
        16 => [28, 7, 45, 3, 46]
    ];

    /**
     * Row and column centres of the alignment patterns, per version.
     */
    private static $alignmentTable = [
        1  => [],
        2  => [6, 18],
        3  => [6, 22],
        4  => [6, 26],
        5  => [6, 30],
        6  => [6, 34],
        7  => [6, 22, 38],
        8  => [6, 24, 42],
        9  => [6, 26, 46],
        10 => [6, 28, 50],
        11 => [6, 30, 54],
        12 => [6, 32, 58],
        13 => [6, 34, 62],
        14 => [6, 26, 46, 66],
        15 => [6, 26, 48, 70],
        16 => [6, 26, 50, 74]
    ];

    private static $expTable = null;

    private static $logTable = null;

    /**
     * The symbol as rows of 0 and 1, dark being 1.
     *
     * @param $text string
     * @param $forcedMask int|null only for tests, which compare against a reference
     *                             encoder one mask at a time
     * @return array|false false if the text is too long to encode
     */
    public static function matrix($text, $forcedMask = null)
    {
        $text = (string)$text;

        $version = self::pickVersion(strlen($text));

        if (!$version) {
            return false;
        }

        $size = self::sizeFor($version);

        $modules = array_fill(0, $size, array_fill(0, $size, 0));
        $reserved = array_fill(0, $size, array_fill(0, $size, false));

        self::drawFunctionPatterns($modules, $reserved, $version, $size);
        self::placeData($modules, $reserved, self::buildCodewords($text, $version), $size);

        if ($forcedMask !== null) {
            $best = self::applyMask($modules, $reserved, (int)$forcedMask, $size);
            self::drawFormatInfo($best, (int)$forcedMask, $size);

            return $best;
        }

        $best = null;
        $bestMask = 0;
        $bestPenalty = null;

        /*
         * Scored before the format bits are written, with that whole region still
         * light. Reading the specification alone one might well score the finished
         * symbol instead, but every established encoder scores it this way, and the
         * difference is not academic: scored the other way this picked a mask that a
         * real scanner failed to read on roughly one provisioning URI in ten. Which
         * mask wins changes nothing about what the symbol decodes to - it is a
         * legibility heuristic - so the tie is broken in favour of what scanners have
         * actually been tested against.
         */
        for ($mask = 0; $mask < 8; $mask++) {
            $candidate = self::applyMask($modules, $reserved, $mask, $size);

            $penalty = self::penalty($candidate, $size);

            if ($bestPenalty === null || $penalty < $bestPenalty) {
                $bestPenalty = $penalty;
                $bestMask = $mask;
                $best = $candidate;
            }
        }

        self::drawFormatInfo($best, $bestMask, $size);

        return $best;
    }

    /**
     * The symbol as an SVG document.
     *
     * @param $text string
     * @param $args array size in pixels, quiet zone in modules, accessible label
     * @return string empty if the text cannot be encoded
     */
    public static function svg($text, $args = [])
    {
        $matrix = self::matrix($text);

        if (!$matrix) {
            return '';
        }

        $args = array_merge([
            'size'   => 200,
            'margin' => 4,
            'label'  => ''
        ], $args);

        $count = count($matrix);
        $margin = max(0, (int)$args['margin']);
        $span = $count + $margin * 2;
        $pixels = max(1, (int)$args['size']);

        /*
         * Runs of adjacent dark modules become a single rectangle. A version 8 symbol
         * holds around two and a half thousand modules, and one element each makes for
         * a needlessly heavy page.
         */
        $path = '';

        foreach ($matrix as $y => $row) {
            $runStart = null;

            for ($x = 0; $x <= $count; $x++) {
                $dark = $x < $count && $row[$x] === 1;

                if ($dark && $runStart === null) {
                    $runStart = $x;
                } elseif (!$dark && $runStart !== null) {
                    $width = $x - $runStart;
                    $path .= 'M' . ($runStart + $margin) . ' ' . ($y + $margin);
                    $path .= 'h' . $width . 'v1h-' . $width . 'z';
                    $runStart = null;
                }
            }
        }

        $svg = '<svg xmlns="http://www.w3.org/2000/svg" width="' . $pixels . '" height="' . $pixels . '"';
        $svg .= ' viewBox="0 0 ' . $span . ' ' . $span . '" shape-rendering="crispEdges"';
        $svg .= ' role="img" aria-label="' . esc_attr((string)$args['label']) . '">';
        $svg .= '<rect width="' . $span . '" height="' . $span . '" fill="#ffffff"/>';
        $svg .= '<path d="' . $path . '" fill="#000000"/>';
        $svg .= '</svg>';

        return $svg;
    }

    /**
     * @param $version int
     * @return int
     */
    private static function sizeFor($version)
    {
        return $version * 4 + 17;
    }

    /**
     * How many bytes fit at this version, once the mode and length headers are paid for.
     *
     * @param $version int
     * @return int
     */
    private static function capacityFor($version)
    {
        $header = 4 + ($version < 10 ? 8 : 16);

        return (int)floor((self::dataCodewords($version) * 8 - $header) / 8);
    }

    /**
     * @param $version int
     * @return int
     */
    private static function dataCodewords($version)
    {
        list($ecPerBlock, $g1Blocks, $g1Words, $g2Blocks, $g2Words) = self::$blockTable[$version];

        return $g1Blocks * $g1Words + $g2Blocks * $g2Words;
    }

    /**
     * The smallest version the text fits in.
     *
     * @param $length int
     * @return int|false
     */
    private static function pickVersion($length)
    {
        foreach (array_keys(self::$blockTable) as $version) {
            if ($length <= self::capacityFor($version)) {
                return $version;
            }
        }

        return false;
    }

    /**
     * Encodes the text, splits it into blocks, adds the error correction and
     * interleaves the lot into the final codeword stream.
     *
     * @param $text string
     * @param $version int
     * @return array
     */
    private static function buildCodewords($text, $version)
    {
        list($ecPerBlock, $g1Blocks, $g1Words, $g2Blocks, $g2Words) = self::$blockTable[$version];

        $bits = '0100'; // byte mode
        $bits .= str_pad(decbin(strlen($text)), $version < 10 ? 8 : 16, '0', STR_PAD_LEFT);

        for ($i = 0, $len = strlen($text); $i < $len; $i++) {
            $bits .= str_pad(decbin(ord($text[$i])), 8, '0', STR_PAD_LEFT);
        }

        $capacityBits = self::dataCodewords($version) * 8;

        // Terminator, then out to a whole codeword, then alternating pad bytes.
        $bits .= str_repeat('0', min(4, $capacityBits - strlen($bits)));

        if (strlen($bits) % 8) {
            $bits .= str_repeat('0', 8 - strlen($bits) % 8);
        }

        $padding = ['11101100', '00010001'];
        $padIndex = 0;

        while (strlen($bits) < $capacityBits) {
            $bits .= $padding[$padIndex++ % 2];
        }

        $data = array_map('bindec', str_split($bits, 8));

        $blocks = [];
        $offset = 0;

        foreach ([[$g1Blocks, $g1Words], [$g2Blocks, $g2Words]] as $group) {
            for ($b = 0; $b < $group[0]; $b++) {
                $blockData = array_slice($data, $offset, $group[1]);
                $offset += $group[1];

                $blocks[] = [
                    'data' => $blockData,
                    'ec'   => self::errorCorrection($blockData, $ecPerBlock)
                ];
            }
        }

        /*
         * Interleaved, so damage to one part of the symbol spreads across every block
         * rather than destroying one of them outright - which is the point of blocks.
         */
        $out = [];
        $maxData = max($g1Words, $g2Words);

        for ($i = 0; $i < $maxData; $i++) {
            foreach ($blocks as $block) {
                if (isset($block['data'][$i])) {
                    $out[] = $block['data'][$i];
                }
            }
        }

        for ($i = 0; $i < $ecPerBlock; $i++) {
            foreach ($blocks as $block) {
                $out[] = $block['ec'][$i];
            }
        }

        return $out;
    }

    /**
     * Reed-Solomon over GF(256): the remainder of the message divided by the generator.
     *
     * @param $data array
     * @param $ecLength int
     * @return array
     */
    private static function errorCorrection($data, $ecLength)
    {
        self::buildGaloisTables();

        $generator = self::generatorPolynomial($ecLength);

        $remainder = array_merge($data, array_fill(0, $ecLength, 0));

        for ($i = 0, $count = count($data); $i < $count; $i++) {
            $factor = $remainder[$i];

            if ($factor === 0) {
                continue;
            }

            $logFactor = self::$logTable[$factor];

            foreach ($generator as $j => $coefficient) {
                $remainder[$i + $j] ^= self::$expTable[(self::$logTable[$coefficient] + $logFactor) % 255];
            }
        }

        return array_slice($remainder, count($data));
    }

    /**
     * @param $degree int
     * @return array
     */
    private static function generatorPolynomial($degree)
    {
        self::buildGaloisTables();

        $poly = [1];

        for ($i = 0; $i < $degree; $i++) {
            $next = array_fill(0, count($poly) + 1, 0);

            foreach ($poly as $j => $coefficient) {
                $next[$j] ^= $coefficient;

                if ($coefficient !== 0) {
                    $next[$j + 1] ^= self::$expTable[(self::$logTable[$coefficient] + $i) % 255];
                }
            }

            $poly = $next;
        }

        return $poly;
    }

    /**
     * @return void
     */
    private static function buildGaloisTables()
    {
        if (self::$expTable !== null) {
            return;
        }

        self::$expTable = [];
        self::$logTable = [];

        $value = 1;

        for ($i = 0; $i < 256; $i++) {
            self::$expTable[$i] = $value;

            if ($i < 255) {
                self::$logTable[$value] = $i;
            }

            $value <<= 1;

            if ($value & 0x100) {
                $value ^= 0x11D; // the primitive polynomial QR is defined over
            }
        }
    }

    /**
     * Finders, separators, timing, alignment, the dark module, the version bits, and
     * the space kept clear for the format bits.
     *
     * Everything drawn here is marked reserved, which is what keeps the data walk and
     * the mask off it.
     *
     * @param $modules array
     * @param $reserved array
     * @param $version int
     * @param $size int
     * @return void
     */
    private static function drawFunctionPatterns(&$modules, &$reserved, $version, $size)
    {
        foreach ([[0, 0], [0, $size - 7], [$size - 7, 0]] as $corner) {
            self::drawFinder($modules, $reserved, $corner[0], $corner[1], $size);
        }

        for ($i = 8; $i < $size - 8; $i++) {
            $bit = ($i % 2 === 0) ? 1 : 0;

            $modules[6][$i] = $bit;
            $reserved[6][$i] = true;

            $modules[$i][6] = $bit;
            $reserved[$i][6] = true;
        }

        foreach (self::$alignmentTable[$version] as $row) {
            foreach (self::$alignmentTable[$version] as $col) {
                // The three finder corners already own their space.
                if (($row === 6 && $col === 6)
                    || ($row === 6 && $col === $size - 7)
                    || ($row === $size - 7 && $col === 6)) {
                    continue;
                }

                self::drawAlignment($modules, $reserved, $row, $col);
            }
        }

        // Kept clear for the format bits, which are written once a mask is chosen.
        for ($i = 0; $i <= 8; $i++) {
            $reserved[8][$i] = true;
            $reserved[$i][8] = true;
        }

        for ($i = 0; $i < 8; $i++) {
            $reserved[8][$size - 1 - $i] = true;
            $reserved[$size - 1 - $i][8] = true;
        }

        // The dark module is reserved here but written with the format bits, so that it
        // is absent while the masks are being scored - as the reference encoders do.
        $reserved[$size - 8][8] = true;

        self::drawVersionInfo($modules, $reserved, $version, $size);
    }

    /**
     * @param $modules array
     * @param $reserved array
     * @param $row int
     * @param $col int
     * @param $size int
     * @return void
     */
    private static function drawFinder(&$modules, &$reserved, $row, $col, $size)
    {
        // A module wider than the pattern on every side: that border is the separator.
        for ($r = -1; $r <= 7; $r++) {
            for ($c = -1; $c <= 7; $c++) {
                $y = $row + $r;
                $x = $col + $c;

                if ($y < 0 || $y >= $size || $x < 0 || $x >= $size) {
                    continue;
                }

                $onRing = ($r === 0 || $r === 6) && $c >= 0 && $c <= 6;
                $onSide = ($c === 0 || $c === 6) && $r >= 0 && $r <= 6;
                $inCore = $r >= 2 && $r <= 4 && $c >= 2 && $c <= 4;

                $modules[$y][$x] = ($onRing || $onSide || $inCore) ? 1 : 0;
                $reserved[$y][$x] = true;
            }
        }
    }

    /**
     * @param $modules array
     * @param $reserved array
     * @param $row int
     * @param $col int
     * @return void
     */
    private static function drawAlignment(&$modules, &$reserved, $row, $col)
    {
        for ($r = -2; $r <= 2; $r++) {
            for ($c = -2; $c <= 2; $c++) {
                $modules[$row + $r][$col + $c] = (max(abs($r), abs($c)) !== 1) ? 1 : 0;
                $reserved[$row + $r][$col + $c] = true;
            }
        }
    }

    /**
     * The version is spelled out in the symbol itself from version 7 up, since by then
     * a scanner can no longer infer it from the size alone reliably enough.
     *
     * @param $modules array
     * @param $reserved array
     * @param $version int
     * @param $size int
     * @return void
     */
    private static function drawVersionInfo(&$modules, &$reserved, $version, $size)
    {
        if ($version < 7) {
            return;
        }

        $remainder = $version;

        for ($i = 0; $i < 12; $i++) {
            $remainder = ($remainder << 1) ^ ((($remainder >> 11) & 1) * 0x1F25);
        }

        $bits = ($version << 12) | $remainder;

        for ($i = 0; $i < 18; $i++) {
            $bit = ($bits >> $i) & 1;
            $row = (int)floor($i / 3);
            $col = $size - 11 + $i % 3;

            $modules[$row][$col] = $bit;
            $reserved[$row][$col] = true;

            $modules[$col][$row] = $bit;
            $reserved[$col][$row] = true;
        }
    }

    /**
     * Walks the free modules in the order the specification lays down: two columns at a
     * time from the bottom right, alternating up and down, skipping the timing column.
     *
     * @param $modules array
     * @param $reserved array
     * @param $codewords array
     * @param $size int
     * @return void
     */
    private static function placeData(&$modules, $reserved, $codewords, $size)
    {
        $bits = '';

        foreach ($codewords as $codeword) {
            $bits .= str_pad(decbin($codeword), 8, '0', STR_PAD_LEFT);
        }

        $index = 0;
        $total = strlen($bits);
        $upwards = true;

        for ($col = $size - 1; $col > 0; $col -= 2) {
            if ($col === 6) {
                $col = 5; // column 6 is the vertical timing pattern
            }

            for ($i = 0; $i < $size; $i++) {
                $row = $upwards ? $size - 1 - $i : $i;

                for ($c = 0; $c < 2; $c++) {
                    $x = $col - $c;

                    if ($reserved[$row][$x]) {
                        continue;
                    }

                    // Anything past the end of the stream is a remainder bit, always light.
                    $modules[$row][$x] = ($index < $total && $bits[$index] === '1') ? 1 : 0;
                    $index++;
                }
            }

            $upwards = !$upwards;
        }
    }

    /**
     * Returns a masked copy, leaving the function patterns alone.
     *
     * @param $modules array
     * @param $reserved array
     * @param $mask int
     * @param $size int
     * @return array
     */
    private static function applyMask($modules, $reserved, $mask, $size)
    {
        for ($row = 0; $row < $size; $row++) {
            for ($col = 0; $col < $size; $col++) {
                if (!$reserved[$row][$col] && self::maskApplies($mask, $row, $col)) {
                    $modules[$row][$col] ^= 1;
                }
            }
        }

        return $modules;
    }

    /**
     * @param $mask int
     * @param $row int
     * @param $col int
     * @return bool
     */
    private static function maskApplies($mask, $row, $col)
    {
        switch ($mask) {
            case 0:
                return ($row + $col) % 2 === 0;
            case 1:
                return $row % 2 === 0;
            case 2:
                return $col % 3 === 0;
            case 3:
                return ($row + $col) % 3 === 0;
            case 4:
                return ((int)floor($row / 2) + (int)floor($col / 3)) % 2 === 0;
            case 5:
                return ($row * $col) % 2 + ($row * $col) % 3 === 0;
            case 6:
                return (($row * $col) % 2 + ($row * $col) % 3) % 2 === 0;
            default:
                return ((($row + $col) % 2) + (($row * $col) % 3)) % 2 === 0;
        }
    }

    /**
     * @param $matrix array
     * @param $mask int
     * @param $size int
     * @return void
     */
    private static function drawFormatInfo(&$matrix, $mask, $size)
    {
        // 00 is level M; those five bits are extended by a BCH code, then masked.
        $format = $mask;
        $remainder = $format;

        for ($i = 0; $i < 10; $i++) {
            $remainder = ($remainder << 1) ^ ((($remainder >> 9) & 1) * 0x537);
        }

        $bits = (($format << 10) | $remainder) ^ 0x5412;

        /*
         * The fifteen bits are written twice, and the two copies run in opposite
         * directions: the top left copy reads most significant bit first along row 8
         * and least significant bit first down column 8, so that a symbol with one
         * corner destroyed can still be read from the other.
         */
        for ($i = 0; $i <= 5; $i++) {
            $matrix[8][$i] = ($bits >> (14 - $i)) & 1;
            $matrix[$i][8] = ($bits >> $i) & 1;
        }

        $matrix[8][7] = ($bits >> 8) & 1;
        $matrix[8][8] = ($bits >> 7) & 1;
        $matrix[7][8] = ($bits >> 6) & 1;

        for ($i = 0; $i <= 6; $i++) {
            $matrix[$size - 1 - $i][8] = ($bits >> (14 - $i)) & 1;
        }

        for ($i = 0; $i <= 7; $i++) {
            $matrix[8][$size - 8 + $i] = ($bits >> (7 - $i)) & 1;
        }

        $matrix[$size - 8][8] = 1; // the dark module, never part of the format bits
    }

    /**
     * The four penalty rules, used to pick the mask giving the symbol a scanner finds
     * easiest: no long uniform runs, no solid blocks, nothing resembling a finder
     * pattern, and a roughly even balance of dark and light.
     *
     * @param $matrix array
     * @param $size int
     * @return int
     */
    private static function penalty($matrix, $size)
    {
        $score = 0;

        // Runs of five or more along a row or column.
        for ($i = 0; $i < $size; $i++) {
            foreach ([true, false] as $horizontal) {
                $runValue = -1;
                $runLength = 0;

                for ($j = 0; $j < $size; $j++) {
                    $value = $horizontal ? $matrix[$i][$j] : $matrix[$j][$i];

                    if ($value === $runValue) {
                        $runLength++;
                        continue;
                    }

                    if ($runLength >= 5) {
                        $score += 3 + ($runLength - 5);
                    }

                    $runValue = $value;
                    $runLength = 1;
                }

                if ($runLength >= 5) {
                    $score += 3 + ($runLength - 5);
                }
            }
        }

        // Any two by two block of a single colour.
        for ($row = 0; $row < $size - 1; $row++) {
            for ($col = 0; $col < $size - 1; $col++) {
                $value = $matrix[$row][$col];

                if ($value === $matrix[$row][$col + 1]
                    && $value === $matrix[$row + 1][$col]
                    && $value === $matrix[$row + 1][$col + 1]) {
                    $score += 3;
                }
            }
        }

        // Anything a scanner could mistake for a finder pattern.
        for ($i = 0; $i < $size; $i++) {
            $rowBits = '';
            $colBits = '';

            for ($j = 0; $j < $size; $j++) {
                $rowBits .= $matrix[$i][$j];
                $colBits .= $matrix[$j][$i];
            }

            foreach (['10111010000', '00001011101'] as $needle) {
                $score += 40 * substr_count($rowBits, $needle);
                $score += 40 * substr_count($colBits, $needle);
            }
        }

        // How far the balance of dark modules strays from half.
        $dark = 0;

        foreach ($matrix as $row) {
            $dark += array_sum($row);
        }

        $percent = ($dark * 100) / ($size * $size);

        return $score + 10 * (int)floor(abs($percent - 50) / 5);
    }
}
