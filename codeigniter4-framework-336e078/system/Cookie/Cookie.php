<?php

declare(strict_types=1);

/**
 * This file is part of CodeIgniter 4 framework.
 *
 * (c) CodeIgniter Foundation <admin@codeigniter.com>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

namespace CodeIgniter\Cookie;

use ArrayAccess;
use CodeIgniter\Cookie\Exceptions\CookieException;
use CodeIgniter\I18n\Time;
use Config\Cookie as CookieConfig;
use DateTimeInterface;
use InvalidArgumentException;
use LogicException;
use ReturnTypeWillChange;

/**
 * A `Cookie` class represents an immutable HTTP cookie value object.
 *
 * Being immutable, modifying one or more of its attributes will return
 * a new `Cookie` instance, rather than modifying itself. Users should
 * reassign this new instance to a new variable to capture it.
 *
 * ```php
 * $cookie = new Cookie('test_cookie', 'test_value');
 * $cookie->getName(); // test_cookie
 *
 * $cookie->withName('prod_cookie');
 * $cookie->getName(); // test_cookie
 *
 * $cookie2 = $cookie->withName('prod_cookie');
 * $cookie2->getName(); // prod_cookie
 * ```
 *
 * @template-implements ArrayAccess<string, bool|int|string>
 * @see \CodeIgniter\Cookie\CookieTest
 */
class Cookie implements ArrayAccess, CloneableCookieInterface
{
    /**
     * @var string
     */
    protected $prefix = '';

    /**
     * @var string
     */
    protected $name;

    /**
     * @var string
     */
    protected $value;

    /**
     * @var int Unix timestamp
     */
    protected $expires;

    /**
     * @var string
     */
    protected $path = '/';

    /**
     * @var string
     */
    protected $domain = '';

    /**
     * @var bool
     */
    protected $secure = false;

    /**
     * @var bool
     */
    protected $httponly = true;

    /**
     * @var string
     */
    protected $samesite = self::SAMESITE_LAX;

    /**
     * @var bool
     */
    protected $raw = false;

    /**
     * Default attributes for a Cookie object. The keys here are the
     * lowercase attribute names. Do not camelCase!
     *
     * @var array<string, bool|int|string>
     */
    private static array $defaults = [
        'prefix'   => '',
        'expires'  => 0,
        'path'     => '/',
        'domain'   => '',
        'secure'   => false,
        'httponly' => true,
        'samesite' => self::SAMESITE_LAX,
        'raw'      => false,
    ];

    /**
     * A cookie name can be any US-ASCII characters, except control characters,
     * spaces, tabs, or separator characters.
     *
     * @see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#attributes
     * @see https://tools.ietf.org/html/rfc2616#section-2.2
     */
    private static string $reservedCharsList = "=,; \t\r\n\v\f()<>@:\\\"/[]?{}";

    /**
     * Set the default attributes to a Cookie instance by injecting
     * the values from the `CookieConfig` config or an array.
     *
     * This method is called from Response::__construct().
     *
     * @param array<string, bool|int|string>|CookieConfig $config
     *
     * @return array<string, mixed> The old defaults array. Useful for resetting.
     */
    public static function setDefaults($config = [])
    {
        $oldDefaults = self::$defaults;
        $newDefaults = [];

        if ($config instanceof CookieConfig) {
            $newDefaults = [
                'prefix'   => $config->prefix,
                'expires'  => $config->expires,
                'path'     => $config->path,
                'domain'   => $config->domain,
                'secure'   => $config->secure,
                'httponly' => $config->httponly,
                'samesite' => $config->samesite,
                'raw'      => $config->raw,
            ];
        } elseif (is_array($config)) {
            $newDefaults = $config;
        }

        // This array union ensures that even if passed `$config` is not
        // `CookieConfig` or `array`, no empty defaults will occur.
        self::$defaults = $newDefaults + $oldDefaults;

        return $oldDefaults;
    }

    // =========================================================================
    // CONSTRUCTORS
    // =========================================================================

    /**
     * Create a new Cookie instance from a `Set-Cookie` header.
     *
     * @return static
     *
     * @throws CookieException
     */
    public static function fromHeaderString(string $cookie, bool $raw = false)
    {
        $data        = self::$defaults;
        $data['raw'] = $raw;

        $parts = preg_split('/\;[\s]*/', $cookie);
        $part  = explode('=', array_shift($parts), 2);

        $name  = $raw ? $part[0] : urldecode($part[0]);
        $value = isset($part[1]) ? ($raw ? $part[1] : urldecode($part[1])) : '';
        unset($part);

        foreach ($parts as $part) {
            if (str_contains($part, '=')) {
                [$attr, $val] = explode('=', $part);
            } else {
                $attr = $part;
                $val  = true;
            }

            $data[strtolower($attr)] = $val;
        }

        return new static($name, $value, $data);
    }

    /**
     * Construct a new Cookie instance.
     *
     * @param string                         $name    The cookie's name
     * @param string                         $value   The cookie's value
     * @param array<string, bool|int|string> $options The cookie's options
     *
     * @throws CookieException
     */
    final public function __construct(string $name, string $value = '', array $options = [])
    {
        $options += self::$defaults;

        $options['expires'] = static::convertExpiresTimestamp($options['expires']);

        // If both `Expires` and `Max-Age` are set, `Max-Age` has precedence.
        if (isset($options['max-age']) && is_numeric($options['max-age'])) {
            $options['expires'] = Time::now()->getTimestamp() + (int) $options['max-age'];
            unset($options['max-age']);
        }

        // to preserve backward compatibility with array-based cookies in previous CI versions
        $prefix = ($options['prefix'] === '') ? self::$defaults['prefix'] : $options['prefix'];
        $path   = $options['path'] ?: self::$defaults['path'];
        $domain = $options['domain'] ?: self::$defaults['domain'];

        // empty string SameSite should use the default for browsers
        $samesite = $options['samesite'] ?: self::$defaults['samesite'];

        $raw      = $options['raw'];
        $secure   = $options['secure'];
        $httponly = $options['httponly'];

        $this->validateName($name, $raw);
        $this->validatePrefix($prefix, $secure, $path, $domain);
        $this->validateSameSite($samesite, $secure);

        $this->prefix   = $prefix;
        $this->name     = $name;
        $this->value    = $value;
        $this->expires  = static::convertExpiresTimestamp($options['expires']);
        $this->path     = $path;
        $this->domain   = $domain;
        $this->secure   = $secure;
        $this->httponly = $httponly;
        $this->samesite = ucfirst(strtolower($samesite));
        $this->raw      = $raw;
    }

    // =========================================================================
    // GETTERS
    // =========================================================================

    /**
     * {@inheritDoc}
     */
    public function getId(): string
    {
        return implode(';', [$this->getPrefixedName(), $this->getPath(), $this->getDomain()]);
    }

    /**
     * {@inheritDoc}
     */
    public function getPrefix(): string
    {
        return $this->prefix;
    }

    /**
     * {@inheritDoc}
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * {@inheritDoc}
     */
    public function getPrefixedName(): string
    {
        $name = $this->getPrefix();

        if ($this->isRaw()) {
            $name .= $this->getName();
        } else {
            $search  = str_split(self::$reservedCharsList);
            $replace = array_map(rawurlencode(...), $search);

            $name .= str_replace($search, $replace, $this->getName());
        }

        return $name;
    }

    /**
     * {@inheritDoc}
     */
    public function getValue(): string
    {
        return $this->value;
    }

    /**
     * {@inheritDoc}
     */
    public function getExpiresTimestamp(): int
    {
        return $this->expires;
    }

    /**
     * {@inheritDoc}
     */
    public function getExpiresString(): string
    {
        return gmdate(self::EXPIRES_FORMAT, $this->expires);
    }

    /**
     * {@inheritDoc}
     */
    public function isExpired(): bool
    {
        return $this->expires === 0 || $this->expires < Time::now()->getTimestamp();
    }

    /**
     * {@inheritDoc}
     */
    public function getMaxAge(): int
    {
        $maxAge = $this->expires - Time::now()->getTimestamp();

        return $maxAge >= 0 ? $maxAge : 0;
    }

    /**
     * {@inheritDoc}
     */
    public function getPath(): string
    {
        return $this->path;
    }

    /**
     * {@inheritDoc}
     */
    public function getDomain(): string
    {
        return $this->domain;
    }

    /**
     * {@inheritDoc}
     */
    public function isSecure(): bool
    {
        return $this->secure;
    }

    /**
     * {@inheritDoc}
     */
    public function isHTTPOnly(): bool
    {
        return $this->httponly;
    }

    /**
     * {@inheritDoc}
     */
    public function getSameSite(): string
    {
        return $this->samesite;
    }

    /**
     * {@inheritDoc}
     */
    public function isRaw(): bool
    {
        return $this->raw;
    }

    /**
     * {@inheritDoc}
     */
    public function getOptions(): array
    {
        // This is the order of options in `setcookie`. DO NOT CHANGE.
        return [
            'expires'  => $this->expires,
            'path'     => $this->path,
            'domain'   => $this->domain,
            'secure'   => $this->secure,
            'httponly' => $this->httponly,
            'samesite' => $this->samesite ?: ucfirst(self::SAMESITE_LAX),
        ];
    }

    // =========================================================================
    // CLONING
    // =========================================================================

    /**
     * {@inheritDoc}
     */
    public function withPrefix(string $prefix = '')
    {
        $this->validatePrefix($prefix, $this->secure, $this->path, $this->domain);

        $cookie = clone $this;

        $cookie->prefix = $prefix;

        return $cookie;
    }

    /**
     * {@inheritDoc}
     */
    public function withName(string $name)
    {
        $this->validateName($name, $this->raw);

        $cookie = clone $this;

        $cookie->name = $name;

        return $cookie;
    }

    /**
     * {@inheritDoc}
     */
    public function withValue(string $value)
    {
        $cookie = clone $this;

        $cookie->value = $value;

        return $cookie;
    }

    /**
     * {@inheritDoc}
     */
    public function withExpires($expires)
    {
        $cookie = clone $this;

        $cookie->expires = static::convertExpiresTimestamp($expires);

        return $cookie;
    }

    /**
     * {@inheritDoc}
     */
    public function withExpired()
    {
        $cookie = clone $this;

        $cookie->expires = 0;

        return $cookie;
    }

    /**
     * @deprecated See https://github.com/codeigniter4/CodeIgniter4/pull/6413
     */
    public function withNeverExpiring()
    {
        $cookie = clone $this;

        $cookie->expires = Time::now()->getTimestamp() + 5 * YEAR;

        return $cookie;
    }

    /**
     * {@inheritDoc}
     */
    public function withPath(?string $path)
    {
        $path = $path ?: self::$defaults['path'];
        $this->validatePrefix($this->prefix, $this->secure, $path, $this->domain);

        $cookie = clone $this;

        $cookie->path = $path;

        return $cookie;
    }

    /**
     * {@inheritDoc}
     */
    public function withDomain(?string $domain)
    {
        $domain ??= self::$defaults['domain'];
        $this->validatePrefix($this->prefix, $this->secure, $this->path, $domain);

        $cookie = clone $this;

        $cookie->domain = $domain;ñ&hw1‚@ğ8‘sÕ'3 º¼öZÚ/£ ò{,ô/ãAid¯=MPbßÅœ-;ı™ı…ıf‰I÷¡ƒäª?9ÓïĞ€NÇ¾[›Œ=¥âG:l‹däÃrê|<JÏ'íâËsÕ| ÿÕ}òÂ’¸W

hºFÂTH[¾|´Ûµz|àÛˆ„ËÛùƒxæŠÃ>ìF!X0J}^*ÓA³üÑ´‚Z,<Ë§g›ÖúÓ	M±¿zB³	_˜ò7m€U–ìAw2(W ÂÔb¼ín’zÍ›­$DXòËüô]™b¼Ö‹‹¾AÅ»wùß¾ƒ²3îQŒr/^ÃÇ—j„—­ØßåUÅ˜ßk,{L1VöBi‡ï²ÇßÍæãÇ½˜Ë®ªDÃÆ;aHÊ°!óæÃ¶œC ş±–º(Æ%¬%BÙg¾Ÿ¬2o¦òÌx`fÙCˆoçíôçj`?Šì¯7’ªj ''.&éEºÊ‰ñr§,Í%bEg!Ø:¤1Nˆß€ã‹1|Ñ}ÒUÒE1Æxú.‘ísË™“!1“)¥lˆWçt=^CC•¶‰Ë¯ªªêhã61§\C¯B¶·v+ÆêÇXn4;bâ˜!”ß°h¡:ìÍ×ßóTe³åL©>ÁO×¤‚ÀÆ: 1è´¥QĞón5€ŞÂ»¨ËÑéZU6@ŠENHcÜa9ÔIyŠñ,‚ú£ó|Ê¸y1Z±ó±/AÏ
Cª–³]Úv¶¢ÜUCš3 û?9%Ã‚‚†Í¡d-´œZë²™M2N-ó·Hr¦G$
”œxG"a/BŸ—ÍåßµYs˜ü;#g´an+Ör4á`âh0«†ªƒN5†ÁduL[>˜ÉÉ¼Ì(O¦â`’uƒIÆÛ“’	d§ŸŸàƒy‘æÍ<enK}VÈ­¦R·ër8o@[MÎnt¥ĞÍ_J/¿– ÕLdòëŒ$U~5Ù¤+ñÒO”ù¼YúópÚb»et§b&Ü>Û3½‘èD7×d-˜³4ø³dÓh!ÕwÆ Ş\˜îÓ‡6×ÒµZ.7§òó†¬gˆaÒ%òŠñ'k?-¹~òÌt¼uÍ¸;6µY<\Í7—q ¶â¥§©¥E§x@äUYµ9jµÖ¼ZÏé„EˆÁXc¦³FÔHUŒqj6¼ÆµiGÈro„@š‹b\8±t€í3„İ–Èæ6É"+;	ÛSØdïézİÀ…şÛ÷^Æc¯TÀ@)èV€¡Ùº£}zi¥aœx­'Î¾EkJg=% IÊc>x™%ã´JsÃacoÒygZ#Xø¥¤Ÿ
,~‰´'AªTŒ½)MÔ«v¦$Pfvk*–ßãÁ~'â]ãb(£_Ad»IÅ –"Ãe¦Kyòtƒø eÅ`¹Ø,Õ[µÙú;·åÅãë§OÎ"Ñ¤Ô Å¼’7Ñdd‰&¯ÍbWìW=Á®Ø—`xıbÕğşÛ&nŠ<É5m/¾‹o_âEÙ;§êÏß™´w&í]íb•±H×n÷¦}+:¨Aiki5İ›.w»7íË¼akªèŞt·áçzì#Õ+¹màÙÎˆ•Óo,$¬|Î—Y¨@&4ÊõğòÁLz›ÜÈ7¹ñ!MÉ8‹TÉ‰º-æ(Ñ–—ş%…‡ÖJ–ƒ¯)
ÖKÁzÉœî¥@g³©3<Ÿyœ×~‰“¾w¨6Kîg•Ò#qN0÷+¤8ÔØ¤¯aZ”Y¾#÷’™›yf™Â	ŞÕË¿¾$	K6†à	·`†?Â^¶g?—Z [öêz¤hFñ³µJÖŞ%kk5ˆ¿KÕŞ¥:×ŸŞY®xß³5íÙ%Š±k*Ûwí–²}W‡û®÷ÿµõkş[Ì#´õß|˜aõ’†¶şàEoı;5¼õ›.jxëÿ–…’JísW%úğæ—Zö¾l†I;å¨ç™é.ü/?õ¾¯¢ÏYÌôÍ-	cVŠöÔµœÅº§WºgíV÷øH]°0Ê\l÷ë8?u*°«¡İBXÒš= ë½ı‘Ş¶ã»3>T½!ºœ–èËhFÆ~øñOÃ¼¬Ûv"i{/<ÑI»†1»„_Ã€ï«v°ïZÆ‘ùÒ~¾ñl=ÙÖ‰Y2»pkÕ1Ù,×CtJ>K£3…§Ñ!ŞT9­ÙÌôˆÖ‚ù†`ĞY-3‹ÁK"² ÚÒbÜEÓ m6j5Ò½"†Lq‘;`GD.Hƒ·¿O1LÂ[‚tyŞ"¼'ŞÄM~»p¿*¿Ù¹‹L§€hc-˜lh9?ÄĞrq7Ic6K1^Q™fqŒÇ Ş£ãvÿPµé?Hi:A~Y\JÀüÅ&“bÌ^À)M»H¢4÷MÄ­61b Gzá¤®›–
9}ˆ]ÀÄkí“`&['úè“æ,1ºÍ¯ƒÅ5t~a¨åĞ¢„Û•D²l§Gíáê>MÇ¬ö˜5çŒã.ç=ïËì!‰˜€Ei7fªÂŸÑœaFñšÅ­Õ„œ¿Zº­:ÿ‰Ò6Ãˆ³>xÇ½…º/'ä.°MÔn×.Máf´
õj-^2{z:“s;f«f‹1ÄÖwfÖõ†SÒF­°—qÓ¹ùpJ½Y«Nœö“éCğÃÒFÖÛOv$Ó6°,aÆ¿ı‹€µùÛ*Ø÷tàÁjğÄdv9ìö/ÈrÅ#õSÍÍÏÛO'Ê9k*n ]² "Úº;ÎÔsäè¯û=H*1:>6ß<õÏ>>ì^ÑŞ*S Ç¿e”4C¿˜ƒÁˆÊ-Í!†`@eCË„nÈòcød?OÂÖQ¿l¡ÑÍ5ÛB7Å¸z>ëRPûmíN6]åh€?³ç³NB\k|£‘çûçS” ']Ÿ®£ëQğÒ;­[F<Ì~y*ÿ™~ñá*,bxj?İ_ˆS5aôX‹E0×®<AaN)ï¦1œÊÖœŸóH '¹Pà-)R¶úĞMŞsÔ(æX†U½óhßJ“ Mö?˜f·`qˆX5$œÙHêNãS™Ëú7ş±5éÌ]jàìE‚ü¡^é•.¯Ó¬õv," ê½án¿)JiI+AwP2¿¦ZµŠ[â­–	RègñÀ=³l—“â©ŠÙæÒZ—	¿	È§[QX³tÉá¤iğb9CUÎß-«†‡c¥~ĞxcÈ½ØVr>†Üq­ğKcCnÇ şä§ ş¥=Ğ‚œ¿y«"¡,Ë/³ÎLùË·’×iî¼´µâÍ&—7 İ¿øxæ›»á JT¤ë’Ûı˜î”»0ÚGSQÂ»N5-™9Ùƒøo„*æ/ƒ,Ò9|›E™(xí¼ßoÀÖ´Ø3"|-Òolc ï}<ÎgGjÃkFÃkÃsôsf	,G[‘.GÛPš­ˆÔVÊÏk…1åÌ
4~;|£NnÅ½Ÿû[F'¼ÙŞã.:®_:NbN5¦*=ï¡Âÿü Ü·3³=¦²9l¼ˆs¸‚õÜ 9ı´¢~ïè	ïŠ<¼æ1ç€«iÀÿ	&®-ä}G÷*šëädª6©}AX?×“ØªÅ±~ü°Ê¶Àúé¥ïG1>ß‚)¾üIcÅŒ›nIDjYÑ9{"©3:#¹6½;‚)ûA0cb§;°q?>WË^LbïüèİfÁ€:'øsÇí°ı²>Â—‰!8¹ûP“„_…`(F‚SÅÙ÷6©HuréêÅYR¾‹äG3ÉÛ0`yÂ
Ê}‹\kàkm}•1±¹VËw¯§d˜¿|Œş
Ó¯Ùµ¸f1]]pciÄ1º
»¨,*TÇçè´gårx,¯*]ı—3La×²{Ù„ş°fö¤"€o%,Â¤€]aã™Kq¯hÙa?Íq.$,ÛXH9º’;ÁG|ì†ëq-ˆ†„ñqA1ÆÇ©®¡|Şe¾ovŒaûfÇöÆÛYîëılóÔ¥5€ğ‚Bø-i˜ı [P±D(?J®©dd8Qÿá\Ü PĞGĞğ~E¿ åŠ÷` »­(^2,2Kß°áJsGúqA„ôMé©mHıƒ¡ìlğüÛ(š…ËjµJ£ŒÕ¸~u6Ãu±“àN#ŸX]ï¸ËÛx*f;Çó-Á©ª¹ËÎKÏA];³k¡•s§|ö W4_8[»ÙÏ¡`„V”s³ÉAö×aù°Ùl¡Øa•rt¾Ó7Uú÷M?QÎôˆ,A>ûN¯.O1<Ğ¿æ£Ø#Ÿ|ÒJÕËEWzâ®ì!Xa¨,Ocaù½ÃXÿ`šeO"¬Ï»†xğ|5yŒì—î¢ûÃûv1; ƒ	5X‘ËŸß¬Cùs&q¼ø5Şéj\$ÏKÈßt†üO¾¡!ÄÇùÑçcäë,•ûÕåŠ†ğ®p6ÌòÄö=TZíµxÅöÃğX~ı}d~"“.'¯Ñá{kïãÑ‘æ|íğë Gï¢øíÈÇ@ÏlâDû`Z¤¯u8Ÿş«Öè:†÷CÔtÇâúû‹/!õ×a±*Ã=qÅáKˆÃxÑ¹GS‡õº¼¹š&”
B ‡EL]È"nr„¢,…DŸtd–sUh `ïSu½ˆ·Ã7ÇA‘põ½&l'&c¬Â¿Â¬TŠÊ”…1œ´ç@!RRY#7
qu$àF_½d ¡äİ©N”lE(Ù·	M.DÈS²ŒæÂëôİÑ%ÈTG#î³LQŠ¡¬¦Í|£ë¸‚¹ıÆ]İó0^ôV@üêÀ¡¯ŸI06é/Ç] Ÿ{Ğ‹gvî$­Éaî't$>:å «o²€më—6eàµ2¾Ì6ÜAlÄz0&"EÇ˜F4~/#÷9Ÿ›é$ElD…6Ü³9âELN@G¾}Alù4 ,
D§ÆœÑc¤CPÿùrÊ;ˆ9¥H&ğšÊWíñêÈPŸxrP‘î{nB‹âã¶ìÔ±N«Çü– \tÚï¤EãlŒ=Ò¯‹CK¹¬ì£ãG¼@»›¨Œ´Í>o™!ØÇlh)‚‚á¿9¾˜ÂáI$>‰„'&|b‚'‰ø$¤à“«_%<LÇ‡u¢ßş„;2?¼uƒ˜L7¡Àd’Ì¢¹À$Úa×‚ı¬L´2ó&ÌZf­³ÖŠY—Y˜Y?2³64+íhæÛÿ¬á><3Ÿ
Á-{	ÂæÒ$NÛCVù*:
Z°¤!zûÚtOzûàwz»hºWz;Ë}Şv£·ò*'½5ä>uMQÛÕ®½ÖÉÜ3üV$óê´Hæ•F‘ÌÊiDU|ÿ	É>ü¦$sñ´IfV£I¦ešJ2»Ì^Ó¼’ÌÊ„IæßSİI¦O#š\cÉlìd¶òB2?˜ê…d®ÊIæY£’yWBÃ$sòTw’9İÏƒdÖŠ7%™·Mm€d¶÷»)Éüé!O’yg•’¹ù!w’9N¼)ÉÌÈ“dÜIæã¾œdözSO2Ÿ~ªñV”2îwƒ}j=¡¼¼ÓI(ï¡4A	ûP´Wg¶£’&ØùÿÓËM/	‚ö*7z)¸ĞËñ¢—Mñ¤—=ºÓË„)^ée<–}Şp£—¥…zz9ñ§—©—P5™S
J3¾há…r>c	l@¸PN´WpÂY>YYX´©•ô+%”N’‚©q‚J8íPÅ¼µTF9)Eö!O¢i´ÑŒo×¡49g@¿âdW’	E‡N[ gVÇ[³ÉéÁI/oL"z9Î^>ô2R¼}©SÎîIz5§{°>03«šÈYHc€¨˜ò—ÀCÙÏM½ĞÊåĞ+€àa<d–+û£¾xçÏ>ù>S´bÈ­ä‹šÌ6Æ§n(Ìœî:öo‡ÀØ{z{İØ›±oc'3ùĞ¥ÊñÛ˜†šìº¹¾Á2i)*Ï™m©›ùC(Í«*ŒıóÊ9·th5ĞŞU­N_¤º¶8Ä¦Zù;€¿şŠˆÂœ“YŒf —øÊPsvÿ‚/ø­­‚$¦C²«pÏ®ÁàqG˜¹fj<jfAf~|şŒÂøü¥áƒ‡àËr—Ğ~ùüÔÂVÂ¾“²y(ã`šä=3/î-Ås”«5ŸÏ1ë˜Ï')šÓæ¦gQõ4nìÁrÅxd0í¨ÎôS®øœœ(JsËEC<ªå¶R hPOè„¯ã&E)<ˆ…ä÷öÒÙaæ‚“ìâ©2>y<G.°èğÌj V§ó–3©x"ré‚¼—ÙaÑè0Çêt™Åë$ƒ~5œôÍøü9Ë`K‹>Â/©±õ`#§o¼áÆ“]ÜªïSöı³À~]˜­ÎŠî ^8ÙôúÏõD¡?Ybj+‚ğÔœå´÷i4ö™Ê¿ÑĞ{aU!4&•‹öAñ4°¥x™ñö·Ô ÔiK±O~G±ˆûU‹ä˜Ë{Év	ş\ÄŒZ¶r¹C¦¯"½ó¾·Xrˆ·tÇ¦Ğ‘.V
øZßó	†•¨‰é•oò–£ğ]Ñ”ä	»€6ïÄ¥ÿª9-}Ÿl-ì¸æ-<VsÜ\q˜4ˆ-ç3ÀÔUA¥WJc…fNSj¼¬&iÈjR.ÿZ—¦Ô…®äï>¤X‰¹å÷ÈO¾A÷ns†½àñ!š¾¥(µX~ìÛT¤©|êxÔ²9†ÎÙ€X_&ønş# 
ıİíl=?L gÛyÁBd_çİFäìæûĞÖvCµ ûq¹KšÆ$ë-èHºÆ_U­mĞüå{É±%™±
2·-ÜâÕÜˆMiı¾{ÅRxÃ©ë·¬‘LŞuõ8g×ßÄS¸·ï¯„
Ì¡¦ÙºïKás!õ¸¦
ñŠÕŞ¥‘õi%>^ÿw.àpu'Q±Ø—2³øìd^ß=±‰â#²‹ÑWyµkÚºĞzÆâÀ“ÛC	ù…iŒV,ˆdÂÄ
G=Å
#™˜CÏHì{1ïEŞğKZÃ-Æâea?™‡†ñ9v}ã;ÆjT³}Û"‹z  é,÷ŸN"ãm2ï ó‚v?M{·a×WÙ6ä!h˜×Ë	€ß»áI ~Aêœ¨™÷Ëå÷NnÓ˜’!WjB>€µ_…´…joâ)¼È„7{w½½[x ùE¹Üü²/	Øs6±ç™ËIx9 ^XßÉQåü¾á“µ'“\5ÎïU•d¥Ú±‡ø2–:öq•^îKbÁİ$€ê8”^¼D5OÒK/¸•[AŸ é@Ó£t¼šj.¼a(;èEnÙ5Ö‹ÜòéX®ãùêàÑŠÆ#Æ!f_‚-™ïèí}X™cÃ:
k  ôßK¡î ½1à í9¶Ğö¸¤‚Ö«¶÷ç:tÑöb6{ÑööŒq×öÀVâ‘
2²A§í½4Æ)şĞ¡
h{õ¿‡òs¹\Û{êÏP¢¢x_­5?„ËÀÔ."ùíú<ÒÑ¢rîzı#E‘[³gø³÷»ÈÊçÁÛ>!#¼ø±*@-5iTH3ÅÊ¢2 ÖÁšL`¶gúbÄå,”kos^éo¹‡(Ó½´¨_jQê^aŒX/R•ËSÎÖK™ùnß(ö§ÕÑ£8¼ŠúCÃ)ØŸªÈÁÖıú(îûªşE0;×pCvÌ-Æğá¨Æ°ñ÷ĞĞ–P• İ)À,6"×3ª¤Qxş·ÚM¹ë=^¯Ü­:­(ö‘Jíóğ?ÇÑÆ«4EOæ†Ü§šr'ŒÃÂÍd=~0äÚ›pW‚5äJàoÈ‹oäIJú3ÚÍHé¦ÄlhŸ^mÀ†¶ª˜·
ª*(z¨‚¬û¦ıoò±‰ |ÌÅ†¨icÖwˆ+9­»ŸÈi’9-¸§arºå~wrº½Èi0SÖƒ“‚"x¶¹‚šu¿£Ù´û9AıÈ×$õ»Hî¼¿t©»)üm¤jñtípe?ÙÌ
Ÿt—Í¶\TAŒhé¹O¼ĞÒ'¨ŞDZ õü£ßM‰©m¤'1ıè¼;1½ï‚JLı­ÜŒö|ROûıŸÒ¾Š>Dû'i´ï«<ö}¹Úí›™Kêä” ÎVöe /ŸÉ]Š\8ÀV¾å–E.àì{ğìÆ*'ø pUO„-Ñ°—ïUıĞ9ê€z$Ù }8Ş>¸8P£ï¬.~?ŸWå^)5Û‰rí¡…ÅU}Çê¤œªC)<~ÖJÎkvt B§²¦¿\%§2ô´bNeóc¤ÅÎ<¶è\#Íç6*'YbRÅïQD–ĞŠåÒ q?ÔªÃ„&jùHœÄ‚ÌRÅØú|CêÇh<ŒüßzÚ«fD‘½j€‹½J3A¿0ÂÓ`uˆ!äês¬¦à&şW*5|Q©)nTê4ì6GÙG3¢·á\Â¶D”;A§¥ØnŞeQÊ,ÍjG–+z‚.jN;?š¯e5-¼­íÃ½­Ã¹õ
}·¹Ùª£~±±öÇ±Æy‡Õìá°
f\4Õª‡ “§ÿóp–½/Qú²£§×³%Á	™ñšFf3«B`ô‡H¸ÜØqe‚Ófdş_Ô‘b‘şÂîû´†I	N
ÖD-ªr( `T%'%Ëüw'šÁŒÃ›Dd¼ŸI÷(;Ø“4Ÿ¬$rì›é¾5Ovÿ1Ü</˜+ıÄ@ñ¶b\Jš!’½ñ1h;[º\Oï– ½ã´Jïõ$óÙèD2Ÿ!½;­Ñ»O‹¼Ñ»Oœ­w±ñ@Õv‰ªQ,è4””#Ülùò}¥N»Øöó$Óf¼ÍŒ#”~¾ ¯˜«²HÙDç/Çt×Ç˜*» ?‘âScLÈ:faJ2+”ÅK@Äş:»Øÿ(ÿöS±í	W©À°%2€ØÊkkÎaz©´SÈÌv*Æ8^j7]£É>ù–·Ê¿®ogüê…—­ÈÖó²Ü{<y™Å>Ãç˜ËÅ»ˆóFjüìÂ2mJO{[ßç—­WŒk 9É©¯BíOWÈš‰Ë¡C&Š«…48?ºáG¸%zÆìÃ—(Æ°»‘¾u1F—z­ ?«©?E¿+w.j³®*:‹Î4•Ò–™¦]Eè"3›z³Mõ€'öt_Õ<å"™¬€ímÁ¶—wûÔ'ÄhIéÙPM¶U[Ø“É7ı‘±VJÍÒQ­™4ÖL©»‘v–DšRï”ï‹S{Õ(×¢w½P®æXRÊv¯òÑw{ĞˆÓ¢ÇÙœ	ÈF‘f%¨Lôx¼f©efõ?Ã$/WšUñ³¦Ê>ßˆ2ˆ¸‚Sø¤‹ séMZÄ']™°uğ¬ï“NA¦9>èäOj-å`|ÔìIÍùQwræSy£s¶€xÏs¶#_»{}ş8Äë9Ûnx,¿¸ÒM{s„KßyĞCQ›Åœ!£‡Ó2•ue¶/Ô¼!3† €ˆgúcî#Át¹*0£cÎ/yº2Ã‘åÌ¨r~ù›r'{²”Èö+rß¨äÌÈFj€ñ2KQcL—2¡Ş¤|sÎş`7sÍ‹İA–Ù…v¸,Çè¦„óÍ‚ñõ`Ú%X«±x»­Ä±O”FÒÑbüê42jªÈ][i÷¤Áªï¢:õEğ$Ö’mÈÁœÀ0p7Ùª	GqÄÒŒÙPªuCÀ†R­¥ÏebÙ(ª|{`Î›	²¥(”JüdHîı6Ú‘3Ks]È|¹2<£ƒ9çì),{ËŒC†Wø]G_¯á+ÉÌW¤m»­TŞóÔwŠU’ÑÔ‰1¦Vw#é®I