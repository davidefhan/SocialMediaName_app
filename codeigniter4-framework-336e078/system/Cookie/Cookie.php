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

        $cookie->domain = $domain;�&hw1�@�8�s�'3 ���Z�/���{,��/�Aid�=MPb�Ŝ-;�����f�I�����?9����N��[��=��G:l�d��r�|<J�'�����s�|���}��W

h�F�TH[�|�۵z|�ۈ�����x����>�F!X0J}^*�A��Ѵ�Z,<˧g����	M��zB�	_��7m�U��Aw2(W �Ԑb��n�z͛�$DX����]�b�֋���AŻw�߾��3�Q�r/^�Ǘj������UŘ�k,{L1V�Bi�������ǽ�ˮ�D��;aHʰ!��ö�C ����(�%�%B�g���2o�����x`f�C�o����j`?��7��j�''.&�E�ʉ�r�,�%bEg!�:�1N�߀�1|�}�U�E1�x�.��s˙�!1�)�l�W�t=^CC���˯���h�61�\C�B��v+���Xn4;b�!�߰h�:�����Te��L�>�Oפ���: 1��Q��n5��»�����ZU6@�ENHc�a9�Iy��,����|ʸy1Z���/A�
C���]�v���UC�3 �?9�%Ð���͡d-��Z벙M2N-�Hr�G$
��xG"a/B����ߵYs��;#g���an+�r4�`�h0�����N5��duL[>��ɼ�(O��`�u�I�ۓ�	d�����y���<enK}Vȭ��R��r8o@[MΎnt���_J/�� �Ld��$U~5٤+��O���Y��p�b�et�b&�>�3����D7��d-��4��d�h!�w� �\��Ӈ6�ҵZ.7�����g�a�%���'�k?-�~��t�u͸;6�Y<\�7�q �⥧��E�x@�UY�9j�ּZ��E��Xc��F�HU�qj�6�ƵiG�ro�@��b\8��t��3�ݖ��6�"+;	�S���d��z������^�c�T�@)�V��ٺ�}zi�a�x�'ξEkJg=% I�c>x�%��Js�aco�ygZ#X�����
,~��'A�T��)M��ԫv�$Pfvk*����~'�]�b(�_Ad�I� �"�e�Ky�t�� e�`��,�[���;�����O�"Ѥ� ż�7�dd�&��bW�W=��ؗ`x�b����&n�<�5m/��o_�E�;���ߙ�w&�]�b��H�n��}+:�Aiki5ݛ.w�7�˼ak���t����z�#�+�m��Έ��o,$�|ΗY�@&4ʝ����Lz���7��!�M�8�T����-�(і��%���J���)
�K�zɜ�@g��3<�y��~���w�6K�g��#qN0�+�8�ؤ�aZ�Y�#����yf���	��˿�$	K6��	�`�?�^�g?��Z�[��z�hF�񏳵J��%kk5��K�ޥ:ן�Y�x߳5��%��k*�w햲}W�������k�[�#���|�a������Eo�;5���.jx�����J�sW%���Z���l�I;���.�/?�����Y��͏-	cV��Ե����W�g�V��H]�0�\l��8?u*����BXҚ=�������3>T�!�����hF�Ə~��Oü���v"i{/<�I��1��_À�v��Z����~��l=�։Y2�pk��1�,�CtJ>K�3���!��T9����ւ��`�Y-3��K"����b�E�� m6j5ҽ"�Lq�;`GD.H���O1��L�[�ty�"�'��M~�p�*����L��hc-�lh9?��rq7Ic6K1^Q�fq�� ޣ�v�P��?Hi:A~Y\J���&�b�^�)M��H�4�Mĭ61b�Gz����
9}�]��k�`&['���,�1�ͯ���5t~a������ەD�l�G���>MǬ��5��.�=���!���E�i7f���ќaF��ŭՄ��Z��:���6È�>x����/'�.�M�n�.M�f��
�j-^2{z:�s;f�f�1�ā�wf���S�F���qӹ�pJ�Y�N�����C���F��Ov$�6�,aƿ������*��t��j��dv9��/�r�#�S����O'�9k*n ]� "ں;��s���=H*1:>6�<��>>�^��*S ��e�4C������-�!�`@eC˄n��c�d?O��Q�l���5�B7Ÿz>�RP�m�N�6]�h�?�糝NB\k|�����S� ']����Q��;�[F<�~y*��~��*,bxj?�_�S5a�X�E0׮<�AaN)�1��֜��H '��P�-)�R���M�s�(�X�U��h�J�� M�?�f�`q�X5$��H�N�S���7��5���]j���E���^��.�Ӭ�v," ��n�)JiI+A��wP�2��Z��[⭖	R�g��=�l�������Z�	�	ȧ[QX�t��i�b9CU��-���c�~�xcȽ�Vr>��q��KcCn� �� ��=Ђ��y�"�,�/���L������i�����&�7 ݿ�x曻��JT�����0�GSQ»N5-�9ك�o�*�/�,�9|�E�(x��o����3"|-�olc �}<��gGj�kF�k�s�sf	,G[�.G�P����V��k�1��
4~�;|�NnŽ��[F'�َ��.:�_:NbN5�*=���� ܷ3�=��9l��s���ܠ9���~��	�<��1瀫i��	&�-�}G�*���d�6�}AX?דتű~��ʶ����G1>߂)��Ic���nIDjY�9{"��3:#�6��;�)�A0cb�;��q?>W�^Lb����f��:'�s����>�!8��P��_�`(�F�S���6�Hur���YR���G3��0`y�
�}�\k�km}�1��V�w��d��|���
ӯٵ�f1]�]pci�1�
��,*T���g�rx,�*]��3Laײ{ل��f��"�o%,¤�]a�Kq�hَa?�q.$,�XH9��;�G|��q-�����qA1�ǩ���|�e�ov�a�f����Y���l�ԥ5���B�-i�� [P�D(?J��dd8Q��\� �P�G��~E� ��`����(^2,2K߰�JsG�qA��M�mH����l���(���j�J�����~u6�u���N#��X]���x*f;��-������K�A];�k��s�|��W4_8[��ϡ`��V�s��A��a���l��a�rt��7U���M?Q��,A>�N�.O1<������#�|�J��EWz��!Xa�,Oca���X�`�eO�"�ϻ�x�|5y������v1�; �	5X�˟߬C�s&q��5��j\$ϝK��t���O��!�����c��,���劆�p6����=TZ��x����X~�}d~"��.'���{k���ё�|���G�����@�l�D�`Z��u8�����:��C�t�����/!��a�*��=q��K��xѹGS������&�
B��EL]�"nr��,�D�td�sUh�`�Su����7�A�p��&l'&c���¬T�ʔ�1���@!RRY#7
qu$�F_�d���ݩN�lE(ٷ	M.D�S��������%�TG#��LQ�����|�븂���]��0^�V@������I06�/�]��{Ћgv�$���a�'t$>:� �o��m�6e�2���6�Al�z0&"EǘF4~/#�9���$ElD�6ܳ9�ELN@G��}Al�4 ,
D�Ɯ�c�CP��r�;�9�H&��W����P�xrP��{nB����ԱN���� \t��E�l�=����CK����G�@������>o�!��lh)����9����I$>��'&|b�'��$�����_%<LǇu����;2?�u��L7��d�̢��$�aׂ��L�2�&�Zf��֊Y�Y�Y?2�64+�h�����><3�
�-{	���$N�CV�*:
Z��!z��tOz��wz�h�Wz;�}�v���*'�5�>uMQ��ծ����3�V$��H�F���iDU|�	�>��$s�IfV�I�e�J2���^Ӽ��ʄI��S�I�O#�\c�l�d��B2?��d���I�Y��yWB�$s�Tw�9�σd֊7%��Mm�d���)���!O�yg����!w�9N�)��ȓd��I�㾜d�zSO2�~��V�2�w�}j=����I(��4A	�P�Wg���&�����M/	��*7z)�������M�=��˄)^�e<�}�p����zz9�����P5�S
J3�h�r>c	l@�PN�Wp�Y>Y�YX�����+%�N���q�J8�Pż�TF9)E�!O�i�ьoס49g@��dW�	E�N[�gV��[�����I/oL"z9΍^>�2R�}�S��Iz5�{�>03���YHc�����C��M����А+��a<d�+���x��>�>S�bȭ䋚�6��n(̜�:�o���{z{�؛�oc'3�Х��ۘ��캹��2i)*ϙm���C(ͫ*����9�th5��U��N_���8ĦZ�;������Y��f ���Psv��/����$�C��pϮ��qG��fj<jfAf~|������Ⴧ��r��~����V���y(�`��=3/�-�s��5��1��')����gQ�4n��r�xd0���S����(Js�EC<���R hPO脯�&E)<�������a�悓��2>y<G.����j V��3�x"r邼��a��0��t���$�~5�����9˝`K�>�/���`#�o��Ɠ]ܪ�S����~]��Ί� ^8�����D���?Ybj+��Ԝ��i4��ʿ��{aU!4&���A�4��x����Ԡ�iK�O~G���U���{�v	�\ČZ�r�C��"��Xr��tǦБ.V
�Z��	�����镁o��]�є�	��6�ĥ��9-}�l-츎�-�<Vs�\q�4�-�3��UA�WJc�fNSj���&i�jR.�Z��Ԏ����>�X�����O�A��ns����!���(�X~��T��|�xԲ9���ـX_&�n�# 
���l=�?L g�y�B�d�_��F������vC���q�K��$�-�H��_U�m���{ɱ%��
2�-�����Mi��{�Rx��뷬�L�u�8g���S��﯄
̡�ٺ�K�s!���
��ޥ��i%>^�w.�pu'Q�ؗ2���d^�=���#���Wy�kں�z�����C	��i�V,�d��
G=�
#��C��H�{1�E��KZ�-��ea?����9v}�;�jT�}�"�z  �,��N"�m2� �v?M{�a�W�6�!h���	�߻�I ~AꜨ�����NnӘ�!WjB>��_���jo�)�Ȅ7{w��[x��E�ܐ��/	�s6���Ix9�^X��Q���ᓵ'�\5��U�d�ڱ��2�:�q�^�Kb��$��8�^�D5O�K/��[A���@ӣt��j.�a(;�En�5֋���X�����ъ�#�!f_�-����}X�c��:
k  ��K�1���9������֫���:t��b6{����q����V�
2�A��4�)�С
h{����s�\�{��P��x_�5?����."���<�Ѣr�z�#E�[�g����������>!#���*@-5iTH3�ʢ2 ���L`�g�b��,�ko�s^�o��(ӽ��_jQ�^a�X/R��S��K��n�(���ѣ8���C�)؞�������(����E0;�pCv�-���ư���ЖP� �)�,6"�3��Qx���M��=^�ܭ:�(��J���?��Ɛ�4EO��ܧ�r'����d=~0�ڛpW�5�J�oȋo�IJ�3��H��lh�^m������
��*(z������o���|�ņ�ic�w�+9����i�9-��ar��~wr����i0�Sփ���"x����u��ٴ�9A���$��H�t��)�m�j�t�pe?��
��t�Ͷ\TA�h�O���'��DZ ����M��m�'1��;1��JL��܌��|RO���Ҿ�>D�'i��<��}��훙K�� �V�e /��]�\8�V��E.��{���*'� pUO�-Ѱ��U��9���z$� }8�>�8P��.~?�W�^)5ۉr��U}�ꤜ�C)<~�J�kvt�B����\%�2��bNe�c���<��\#��6*'YbR��QD�Њ�Ҡq?ԪÄ&j�H�Ă�R���|C��h<���zګfD��j���J3A�0��`u�!��s����&�W*5|Q�)nT�4�6G��G3���\¶D�;A���n�eQ�,�jG�+z�.jN;?��e5-���ý��ù�
}��٪��~���Ǳ�y���ឰ
f\4���������p��/Q����׳%�	���Ff3�B`�H���qe��fd�_ԑb�������I	N
�D-�r( `T%'%��w'���ÛDd��I�(;��4��$r��5Ov�1�</�+��@�b\J�!���1h;[�\O� ���J��$���D2�!�;��ѻO��ѻO��w��@�v��Q,�4��#�l��}�N����$�f�͌#�~� ����H�D�/�t�ǘ*��?��ScL�:faJ2+��K@��:���(��S���	W���%2���kk�az��S��v*�8^j7]��>���ʿ�og�ꅗ�����{<y��>����Ż��Fj���2mJO{[�痞�W�k�9ɩ�B�OWȚ�ˡC&���48?��G�%z��×(�����u1F�z� ?��?E�+w.j��*:���4�Җ��]E�"3�z�M��'�t_�<�"����m���w��'��hI��PM�U[ؓ�7���VJ��Q��4�L���v�D�R���S{�(עw�P��XR�v���w{Ј�Ӣ�ٜ	�F�f%�L�x��f�e�f�?�$/W�U��>߈2����S���� s�MZ�']��u��NA�9>��Oj�-�`|��I��Qwr�Sy��s��x�s�#_�{}�8��9�nx,���M{s�K�y�CQ�Ŝ!���2�ue�/Լ!3� ��g�c�#�t�*0�c�/y�2Ñ�̨r~��r'{����+r�����Fj��2KQcL��2�ޤ|s��`7s͋�A�مv�,�覄������`�%X��x��ıO�F�юb��42j��][i�����:�E�$֒m����0�p7٪	�Gq�Ҍ�P�uC��R���eb�(��|{`Λ	��(�J�dH��6ڑ3Ks]�|�2<��9��),{ˌC�W�]G_��+��W�m��T���w�U��ԉ1�Vw#�I