package qa.infosec.testng.netsign.dataprovider;

import cn.com.infosec.jce.provider.InfosecProvider;
import org.testng.annotations.DataProvider;
import qa.infosec.testng.netsign.dataprovider.util.ParameterUtil;
import qa.infosec.testng.netsign.dataprovider.util.ParseCert;
import qa.infosec.testng.netsign.dataprovider.util.ParseFile;
import static qa.infosec.testng.netsign.dataprovider.util.ParameterUtil.*;
import java.security.Security;

/**
 * 数据源
 * <p>Title: NetSignDataProvider</p>
 * <p>Description: </p>
 *
 * @author zhaoyongzhi
 * @date 2020年04月13日
 */
public class NetSignDataProvider {

    static {
        Security.addProvider(new InfosecProvider());
    }

    /**
     * 调用数据源,覆盖SM2和RSA所有证书,正常证书
     *
     * @return 【alg，dn】
     */
    @DataProvider(name = "normal-alg-dn")
    public static Object[][] normalAlgDN() {
        return DataProviderUtil.resolveAlgDN(normalpath);
    }

    /**
     * 调用数据源,覆盖SM2和RSA所有证书,过期证书
     *
     * @return 【alg，dn】
     */
    @DataProvider(name = "expire-alg-dn")
    public static Object[][] expireAlgDN() {
        return DataProviderUtil.resolveAlgDN(expirepath);
    }

    /**
     * 调用数据源,覆盖SM2和RSA所有证书,作废证书
     *
     * @return 【alg，dn】
     */
    @DataProvider(name = "revoke-alg-dn")
    public static Object[][] revokeAlgDN() {
        return DataProviderUtil.resolveAlgDN(revokepath);
    }

    /**
     * 调用数据源,覆盖SM2和RSA所有证书,不受信任证书
     *
     * @return 【alg，dn】
     */
    @DataProvider(name = "nottrust-alg-dn")
    public static Object[][] nottrustAlgDN() {
        return DataProviderUtil.resolveAlgDN(nottrustpath);
    }

    /**
     * 调用数据源,覆盖SM2和RSA所有证书,黑名单证书
     *
     * @return 【alg，dn】
     */
    @DataProvider(name = "blacklist-alg-dn")
    public static Object[][] blacklistAlgDN() {
        return DataProviderUtil.resolveAlgDN(blacklistpath);
    }

    /**
     * 获取机构代码及摘要,对应正常证书
     *
     * @return 【alg，bankcode】
     */
    @DataProvider(name = "normal-alg-bankcode")
    public static Object[][] normalbankCodeAlg() {
        return DataProviderUtil.bankCodeAlg(normalpath);
    }

    /**
     * 获取机构代码及摘要,对应过期证书
     *
     * @return 【alg，bankcode】
     */
    @DataProvider(name = "expire-alg-bankcode")
    public static Object[][] expirebankCodeAlg() {
        return DataProviderUtil.bankCodeAlg(expirepath);
    }

    /**
     * 获取机构代码及摘要,对应作废证书
     *
     * @return 【alg，bankcode】
     */
    @DataProvider(name = "revoke-alg-bankcode")
    public static Object[][] revokebankCodeAlg() {
        return DataProviderUtil.bankCodeAlg(revokepath);
    }

    /**
     * 获取机构代码及摘要,对应不受信任证书
     *
     * @return 【alg，bankcode】
     */
    @DataProvider(name = "nottrust-alg-bankcode")
    public static Object[][] nottrustbankCodeAlg() {
        return DataProviderUtil.bankCodeAlg(nottrustpath);
    }

    /**
     * 获取机构代码及摘要,对应黑名单证书
     *
     * @return 【alg，bankcode】
     */
    @DataProvider(name = "blacklist-alg-bankcode")
    public static Object[][] blacklistbankCodeAlg() {
        return DataProviderUtil.bankCodeAlg(blacklistpath);
    }

    /**
     * 二三类 JSON字符串，加密普通交易报文
     *
     * @return 【json】
     */
    @DataProvider(name = "normal-json")
    public static Object[] jsonData() {
        return DataProviderUtil.JsonDataList();
    }

    /**
     * 二三类 JSON字符串，加密工作密钥密文,正常证书
     *
     * @return 【encdn，json】
     */
    @DataProvider(name = "normal-dn-json")
    public static Object[][] normalJsonKeyTextDN() {
        return DataProviderUtil.keyTextWithDN(normalpath);
    }

    /**
     * 二三类 JSON字符串，加密工作密钥密文,过期证书
     *
     * @return 【encdn，json】
     */
    @DataProvider(name = "expire-dn-json")
    public static Object[][] expireJsonKeyTextDN() {
        return DataProviderUtil.keyTextWithDN(expirepath);
    }

    /**
     * 二三类 JSON字符串，加密工作密钥密文,作废证书
     *
     * @return 【encdn，json】
     */
    @DataProvider(name = "revoke-dn-json")
    public static Object[][] revokeJsonKeyTextDN() {
        return DataProviderUtil.keyTextWithDN(revokepath);
    }

    /**
     * 二三类 JSON字符串，加密工作密钥密文,不受信任证书
     *
     * @return 【encdn，json】
     */
    @DataProvider(name = "nottrust-dn-json")
    public static Object[][] nottrustJsonKeyTextDN() {
        return DataProviderUtil.keyTextWithDN(nottrustpath);
    }

    /**
     * 二三类 JSON字符串，加密工作密钥密文,黑名单证书
     *
     * @return 【encdn，json】
     */
    @DataProvider(name = "blacklist-dn-json")
    public static Object[][] blacklistJsonKeyTextDN() {
        return DataProviderUtil.keyTextWithDN(blacklistpath);
    }

    /**
     * 二三类 JSON字符串，加密及签名报文，正常证书
     *
     * @return 【json，signdn, encdn】
     */
    @DataProvider(name = "normal-json-signdn-encdn")
    public static Object[][] normalJsonSignDNAndEncryDN() {
        return DataProviderUtil.jsonSignDNAndEncryDN(normalpath);
    }

    /**
     * 二三类 JSON字符串，加密及签名报文，过期证书
     *
     * @return 【json，signdn, encdn】
     */
    @DataProvider(name = "expire-json-signdn-encdn")
    public static Object[][] expireJsonSignDNAndEncryDN() {
        return DataProviderUtil.jsonSignDNAndEncryDN(expirepath);
    }

    /**
     * 二三类 JSON字符串，加密及签名报文，作废证书
     *
     * @return 【json，signdn, encdn】
     */
    @DataProvider(name = "revoke-json-signdn-encdn")
    public static Object[][] revokeJsonSignDNAndEncryDN() {
        return DataProviderUtil.jsonSignDNAndEncryDN(revokepath);
    }

    /**
     * 二三类 JSON字符串，加密及签名报文，不受信任证书
     *
     * @return 【json，signdn, encdn】
     */
    @DataProvider(name = "nottrust-json-signdn-encdn")
    public static Object[][] nottrustJsonSignDNAndEncryDN() {
        return DataProviderUtil.jsonSignDNAndEncryDN(nottrustpath);
    }

    /**
     * 二三类 JSON字符串，加密及签名报文，黑名单证书
     *
     * @return 【json，signdn, encdn】
     */
    @DataProvider(name = "blacklist-json-signdn-encdn")
    public static Object[][] blacklistJsonSignDNAndEncryDN() {
        return DataProviderUtil.jsonSignDNAndEncryDN(blacklistpath);
    }

    /**
     * 二三类 JSON字符串，加密及签名报文，正常证书对应行号
     *
     * @return 【json，signbank, encbank】
     */
    @DataProvider(name = "normal-json-signbank-encbank")
    public static Object[][] normalJsonSignAndEncryBank() {
        return DataProviderUtil.jsonSignAndEncryBank(normalpath);
    }

    /**
     * 二三类 JSON字符串，加密及签名报文，过期证书对应行号
     *
     * @return 【json，signbank, encbank】
     */
    @DataProvider(name = "expire-json-signbank-encbank")
    public static Object[][] expireJsonSignAndEncryBank() {
        return DataProviderUtil.jsonSignAndEncryBank(expirepath);
    }

    /**
     * 二三类 JSON字符串，加密及签名报文，作废证书对应行号
     *
     * @return 【json，signbank, encbank】
     */
    @DataProvider(name = "revoke-json-signbank-encbank")
    public static Object[][] revokeJsonSignAndEncryBank() {
        return DataProviderUtil.jsonSignAndEncryBank(revokepath);
    }

    /**
     * 二三类 JSON字符串，加密及签名报文，不受信任证书对应行号
     *
     * @return 【json，signbank, encbank】
     */
    @DataProvider(name = "nottrust-json-signbank-encbank")
    public static Object[][] nottrustJsonSignAndEncryBank() {
        return DataProviderUtil.jsonSignAndEncryBank(nottrustpath);
    }

    /**
     * 二三类 JSON字符串，加密及签名报文，黑名单证书对应行号
     *
     * @return 【json，signbank, encbank】
     */
    @DataProvider(name = "blacklist-json-signbank-encbank")
    public static Object[][] blacklistJsonSignAndEncryBank() {
        return DataProviderUtil.jsonSignAndEncryBank(blacklistpath);
    }

    /**
     * 获取密钥列表中RSA证书主题
     *
     * @return 【dn】
     */
    @DataProvider(name = "rsakeystore-dn")
    public static Object[] getRSAKeystoreDN() {
        return DataProviderUtil.getRSAKeystoreDN();
    }

    /**
     * 获取密钥列表中国密证书主题
     *
     * @return 【dn】
     */
    @DataProvider(name = "sm2keystore-dn")
    public static Object[] getSM2KeystoreDN() {
        return DataProviderUtil.getSM2KeystoreDN();
    }

    /**
     * 获取密钥列表中所有证书主题
     *
     * @return 【dn】
     */
    @DataProvider(name = "keystore-dn")
    public static Object[] getKeystoreDN() {
        return DataProviderUtil.getKeystoreDN();
    }

    /**
     * 只获取rsa证书实体
     *
     * @return 【X509Certificate cert】
     */
    @DataProvider(name = "rsa-cert")
    public static Object[] getRsaCert() {
        return DataProviderUtil.getCert(normalpath, "rsa");
    }

    /**
     * 只获取sm2证书实体
     *
     * @return 【X509Certificate cert】
     */
    @DataProvider(name = "sm2-cert")
    public static Object[] getSM2Cert() {
        return DataProviderUtil.getCert(normalpath, "sm2");
    }

    /**
     * 获取rsa、sm2证书实体
     *
     * @return 【X509Certificate cert】
     */
    @DataProvider(name = "normal-cert")
    public static Object[] getCert() {
        return DataProviderUtil.getCert(normalpath, "all");
    }

    /**
     * 获取rsa、sm2摘要算法
     */
    @DataProvider(name = "alg")
    public static Object[] getAlg() {
        return DataProviderUtil.getAlg();
    }

    /**
     * 获取rsa摘要算法
     */
    @DataProvider(name = "rsa-alg")
    public static Object[] getRsaAlg() {
        return DataProviderUtil.RSAHashArrays();
    }
//===========================================facePayment1.3新增======================================================

    /**
     * 参数为null或""
     *
     * @return 【String】
     */
    @DataProvider(name = "emptys-parameter")
    public static Object[] emptys() {
        return DataProviderUtil.Emptys();
    }

    /**
     * 获取对称算法类型
     * return【symmAlg】
     */
    @DataProvider(name = "symmAlg")
    public static Object[] getSymmetricalAlg() {
        return DataProviderUtil.getSymmetricalAlg(0);
    }

    /**
     * 获取对称算法类型及对称密钥
     * ivlength = 0 返回所有类型对称密钥及算法
     * ivlength = 8 返回类型为3DES/DES/RC4/RC2对称密钥及算法
     * ivlength = 16 返回类型为AES/SM4对称密钥及算法
     * ivEmpty = false 返回所有填充模式
     */
    @DataProvider(name = "symmKey-all-alg")
    public static Object[] getSymmKeyAndAlg() {
        return DataProviderUtil.getSymmKeyAndAlg(0, false);
    }

    /**
     * 获取对称算法类型及对称密钥
     * ivlength = 0 返回所有类型对称密钥及算法
     * ivlength = 8 返回类型为3DES/DES/RC4/RC2对称密钥及算法
     * ivlength = 16 返回类型为AES/SM4对称密钥及算法
     * ivEmpty = true 不返回含有/ECB的填充模式及RC4/RC2对称密钥算法
     */
    @DataProvider(name = "symmKey-all-alg-ivEmpty")
    public static Object[] getSymmKeyAndAlgIVEmpty() {
        return DataProviderUtil.getSymmKeyAndAlg(0, true);
    }

    /**
     * 获取对称算法类型、对称密钥及填充模式
     * ivlength = 0 返回所有类型对称密钥及算法
     *
     * @return 【symmKeyAlg,modePadding】
     */
    @DataProvider(name = "symmKeyAlg-all-modepadding")
    public static Object[][] symmkeyAllAndModePadding() {
        return DataProviderUtil.symmKeyAndModePadding(0, false);
    }

    /**
     * 获取对称算法类型、对称密钥及填充模式
     * ivlength = 8 返回类型为3DES/DES/RC4/RC2对称密钥及算法
     *
     * @return 【symmKeyAlg,modePadding】
     */
    @DataProvider(name = "symmKeyAlg-8-modepadding")
    public static Object[][] symmkeyDESor3DESAndModePadding() {
        return DataProviderUtil.symmKeyAndModePadding(8, false);
    }

    /**
     * 获取对称算法类型、对称密钥及填充模式
     * ivlength = 16 返回类型为AES/SM4对称密钥及算法
     *
     * @return 【symmKeyAlg,modePadding】
     */
    @DataProvider(name = "symmKeyAlg-16-modepadding")
    public static Object[][] symmkeySM4orAESAndModePadding() {
        return DataProviderUtil.symmKeyAndModePadding(16, false);
    }

    /**
     * 获取对称算法类型、对称密钥及填充模式
     * ivlength = 0 返回所有类型对称密钥及算法
     * ivEmpty = true 不返回含有/ECB的填充模式及RC4/RC2对称密钥算法
     *
     * @return 【symmKeyAlg,modePadding】
     */
    @DataProvider(name = "symmKeyAlg-all-modepadding-ivEmpty")
    public static Object[][] symmkeyAllAndModePaddingIVEmpty() {
        return DataProviderUtil.symmKeyAndModePadding(0, true);
    }

    /**
     * 获取对称算法类型、对称密钥及填充模式
     * ivlength = 8 返回类型为3DES/DES/RC4/RC2对称密钥及算法
     * ivEmpty = true 不返回含有/ECB的填充模式及RC4/RC2对称密钥算法
     *
     * @return 【symmKeyAlg,modePadding】
     */
    @DataProvider(name = "symmkeyAlg-8-modepadding-ivEmpty")
    public static Object[][] SymmKey3DESorDESAndModePaddingIVEmpty() {
        return DataProviderUtil.symmKeyAndModePadding(8, true);
    }

    /**
     * 获取对称算法类型、对称密钥及填充模式
     * ivlength = 16 返回类型为AES/SM4对称密钥及算法
     * ivEmpty = true 不返回含有/ECB的填充模式及RC4/RC2对称密钥算法
     *
     * @return 【symmKeyAlg,modePadding】
     */
    @DataProvider(name = "symmKeyAlg-16-modepadding-ivEmpty")
    public static Object[][] symmKeySM4orAESAndModePaddingIVEmpty() {
        return DataProviderUtil.symmKeyAndModePadding(16, true);
    }

    /**
     * 解析symmkey.xml获取对称密钥号、类型、数据
     * ivlength = 0 对称密钥类型为SM4/AES/3DES/DES对称密钥及算法
     *
     * @return 【keylable&type&data】
     */
    @DataProvider(name = "keylable-type-data-0")
    public static Object[] sKeyLableAndTypeAndDataALL() {
        return DataProviderUtil.getKeyLbAndTpAndData(0);
    }

    /**
     * 解析symmkey.xml获取对称密钥号、类型、数据
     * ivlength = 8 对称密钥类型为3DES/DES对称密钥及算法
     *
     * @return 【keylable&type&data】
     */
    @DataProvider(name = "keylable-type-data-8")
    public static Object[] sKeyLableAndTypeAndDataIv8() {
        return DataProviderUtil.getKeyLbAndTpAndData(8);
    }

    /**
     * 解析symmkey.xml获取对称密钥号、类型、数据
     * ivlength = 16 对称密钥类型为SM4/AES对称密钥及算法
     *
     * @return 【keylable&type&data】
     */
    @DataProvider(name = "keylable-type-data-16")
    public static Object[] sKeyLableAndTypeAndDataIv16() {
        return DataProviderUtil.getKeyLbAndTpAndData(16);
    }

    /**
     * 获取对称密钥及填充模式，对称密钥包含keyLable/keyType/keyData
     * ivEmpty = true 返回填充模式不含有/ECB
     * ivlength = 16 对称密钥类型为SM4/AES对称密钥及算法
     *
     * @return 【keylable&type&data,modeAndPadding】
     */
    @DataProvider(name = "keylable-type-data-16-modepadding")
    public static Object[][] symmkeyIv16AndModePadding() {
        return DataProviderUtil.symmKeyWithModePadding(16, true);
    }

    /**
     * 获取对称密钥及填充模式，对称密钥包含keyLable/keyType/keyData
     * ivEmpty = true 返回填充模式不含有/ECB
     * ivlength = 8 对称密钥类型为DES/3DES对称密钥及算法
     *
     * @return 【keylable&type&data,modeAndPadding】
     */
    @DataProvider(name = "keylable-type-data-8-modepadding")
    public static Object[][] symmkeyIv8AndModePadding() {
        return DataProviderUtil.symmKeyWithModePadding(8, true);
    }

    /**
     * 获取对称密钥及填充模式，对称密钥包含keyLable/keyType/keyData
     * ivEmpty = true 返回填充模式不含有/ECB
     * ivlength = 8 对称密钥类型为DES/3DES对称密钥及算法
     *
     * @return 【keylable&type&data,modeAndPadding】
     */
    @DataProvider(name = "keylable-type-data-0-modepadding")
    public static Object[][] symmKeyAllAndModePadding() {
        return DataProviderUtil.symmKeyWithModePadding(0, true);
    }

    /**
     * 获取对称密钥算法类型，填充模式
     * ivEmpty = true 返回填充模式不含有/ECB
     * ivlength = 8 对称密钥类型为DES/3DES对称密钥及算法
     */
    @DataProvider(name = "alg-8-modepadding")
    public static Object[][] algAndModePaddingIv8() {
        return DataProviderUtil.AlgWithModePadding(8, true);
    }

    /**
     * 获取对称密钥算法类型，填充模式
     * ivEmpty = true 返回填充模式不含有/ECB
     * ivlength = 16 对称密钥类型为AES/SM4对称密钥及算法
     */
    @DataProvider(name = "alg-16-modepadding")
    public static Object[][] algAndModePaddingIv16() {
        return DataProviderUtil.AlgWithModePadding(16, true);
    }

    /**
     * 获取对称密钥算法类型，填充模式
     * ivEmpty = true 返回填充模式不含有/ECB
     * ivlength = 0 对称密钥类型为AES/SM4/DES/3DES对称密钥及算法
     */
    @DataProvider(name = "alg-all-modepadding")
    public static Object[][] algAndModePaddingAll() {
        return DataProviderUtil.AlgWithModePadding(0, true);
    }

    /**
     * 获取对称密钥以及证书DN
     * ivlength = 8 对称密钥类型为DES/3DES对称密钥及算法
     */
    @DataProvider(name = "symmkey-8-dn")
    public static Object[][] symmKeyIv8AndDN() {
        return DataProviderUtil.symmKeyWithDN(8);
    }

    /**
     * 获取对称密钥以及证书DN
     * ivlength = 8 对称密钥类型为SM4/AES对称密钥及算法
     */
    @DataProvider(name = "symmkey-16-dn")
    public static Object[][] symmkeyIv16AndDN() {
        return DataProviderUtil.symmKeyWithDN(16);
    }

    /**
     * 获取对称密钥以及证书DN
     * ivlength = 0 对称密钥类型为SM4/AES/DES/3DES对称密钥及算法
     */
    @DataProvider(name = "symmkey-0-dn")
    public static Object[][] symmkeyAllAndDN() {
        return DataProviderUtil.symmKeyWithDN(0);
    }
//===========================================facePayment1.6新增======================================================

    /**
     * 获取非对称填充模式及证书DN
     *
     * @return 【modeAndpadding,dn】
     */
    @DataProvider(name = "modepadding-dn")
    public static Object[][] asymmModeAndPaddingWithDN() {
        return DataProviderUtil.asymmModeAndPaddingWithDN();
    }
//===========================================bcm1.1新增==============================================================

    /**
     * 获取正常RSA证书DN及摘要算法
     *
     * @return [dn, alg]
     */
    @DataProvider(name = "rsadn-normal-alg")
    public static Object[][] rsaNormalCertDNAndAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("DN", true, false, normalpath, "rsa", 0);
    }

    /**
     * 获取过期RSA证书DN及摘要算法
     *
     * @return [dn, alg]
     */
    @DataProvider(name = "rsadn-expire-alg")
    public static Object[][] rsaExpireCertDNAndAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("DN", true, false, expirepath, "rsa", 0);
    }

    /**
     * 获取作废RSA证书DN及摘要算法
     *
     * @return [dn, alg]
     */
    @DataProvider(name = "rsadn-revoke-alg")
    public static Object[][] rsaRevokeCertDNAndAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("DN", true, false, revokepath, "rsa", 0);
    }

    /**
     * 获取不受信任RSA证书DN及摘要算法
     *
     * @return [dn, alg]
     */
    @DataProvider(name = "rsadn-nottrust-alg")
    public static Object[][] rsaNottrustCertDNAndAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("DN", true, false, nottrustpath, "rsa", 0);
    }

    /**
     * 获取正常SM2证书DN及摘要算法
     *
     * @return [dn, alg]
     */
    @DataProvider(name = "sm2dn-normal-alg")
    public static Object[][] sm2NormalCertDNAndAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("DN", true, false, normalpath, "sm2", 0);
    }

    /**
     * 获取过期SM2证书DN及摘要算法
     *
     * @return [dn, alg]
     */
    @DataProvider(name = "sm2dn-expire-alg")
    public static Object[][] sm2ExpireCertDNAndAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("DN", true, false, expirepath, "sm2", 0);
    }

    /**
     * 获取作废SM2证书DN及摘要算法
     *
     * @return [dn, alg]
     */
    @DataProvider(name = "sm2dn-revoke-alg")
    public static Object[][] sm2RevokeCertDNAndAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("DN", true, false, revokepath, "sm2", 0);
    }

    /**
     * 获取不受信任SM2证书DN及摘要算法
     *
     * @return [dn, alg]
     */
    @DataProvider(name = "sm2dn-nottrust-alg")
    public static Object[][] sm2NottrustCertDNAndAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("DN", true, false, nottrustpath, "sm2", 0);
    }
//===========================================abcjew2.8新增==============================================================

    /**
     * 获取所有证书的base64信息以及证书DN
     */
    @DataProvider(name = "allcert-dn")
    public static Object[] getAllBase64CertAndDN() {
        return DataProviderUtil.getBase64CertAndAttr("DN", allcertpath, "all");
    }

    /**
     * 获取正常RSA证书的base64信息以及证书DN
     */
    @DataProvider(name = "normal-rsa-base64cert-dn")
    public static Object[] normalRSABase64CertAndDN() {
        return DataProviderUtil.getBase64CertAndAttr("DN", normalpath, "rsa");
    }

    /**
     * 获取作废RSA证书的base64信息以及证书DN
     */
    @DataProvider(name = "revoke-rsa-base64cert-dn")
    public static Object[] revokeRSABase64CertAndDN() {
        return DataProviderUtil.getBase64CertAndAttr("DN", revokepath, "rsa");
    }

    /**
     * 获取不受信任RSA证书的base64信息以及证书DN
     */
    @DataProvider(name = "nottrust-rsa-base64cert-dn")
    public static Object[] nottrustRSABase64CertAndDN() {
        return DataProviderUtil.getBase64CertAndAttr("DN", nottrustpath, "rsa");
    }

    /**
     * 获取过期RSA证书的base64信息以及证书DN
     */
    @DataProvider(name = "expire-rsa-base64cert-dn")
    public static Object[] expireRSABase64CertAndDN() {
        return DataProviderUtil.getBase64CertAndAttr("DN", expirepath, "rsa");
    }

    /**
     * 获取正常SM2证书的base64信息以及证书DN
     */
    @DataProvider(name = "normal-sm2-base64cert-dn")
    public static Object[] normalSM2Base64CertAndDN() {
        return DataProviderUtil.getBase64CertAndAttr("DN", normalpath, "sm2");
    }

    /**
     * 获取作废SM2证书的base64信息以及证书DN
     */
    @DataProvider(name = "revoke-sm2-base64cert-dn")
    public static Object[] revokeSM2Base64CertAndDN() {
        return DataProviderUtil.getBase64CertAndAttr("DN", revokepath, "sm2");
    }

    /**
     * 获取不受信任SM2证书的base64信息以及证书DN
     */
    @DataProvider(name = "nottrust-sm2-base64cert-dn")
    public static Object[] nottrustSM2Base64CertAndDN() {
        return DataProviderUtil.getBase64CertAndAttr("DN", nottrustpath, "sm2");
    }

    /**
     * 获取过期SM2证书的base64信息以及证书DN
     */
    @DataProvider(name = "expire-sm2-base64cert-dn")
    public static Object[] expireSM2Base64CertAndDN() {
        return DataProviderUtil.getBase64CertAndAttr("DN", expirepath, "sm2");
    }

    /**
     * 获取所有证书的base64信息以及证书SN
     */
    @DataProvider(name = "allcert-sn")
    public static Object[] getAllBase64CertAndSN() {
        return DataProviderUtil.getBase64CertAndAttr("SN", allcertpath, "all");
    }

    /**
     * 获取所有证书的base64信息以及证书BankCode
     */
    @DataProvider(name = "allcert-bankcode")
    public static Object[] getAllBase64CertAndBankCode() {
        return DataProviderUtil.getBase64CertAndBankCode(allcertpath, "all");
    }

    /**
     * 获取所有证书的bankcode
     */
    @DataProvider(name = "bankcode")
    public static Object[] getBankCode() {
        return ParseFile.getBankCode(ParameterUtil.localdetailpath, allcertpath, "all");
    }

    /**
     * 获取所有对称加密算法、证书的base64信息以及证书DN
     *
     * @return [Alg, DN%Base64Cert]
     */
    @DataProvider(name = "symmalg-allcert-dn")
    public static Object[][] getAllSymmAlgWithBase64CertAndDN() {
        return DataProviderUtil.getAlgWithBase64CertAndAttr("DN", allcertpath, "all", 0);
    }

    /**
     * 获取所有对称加密算法、证书的base64信息以及证书SN
     *
     * @return [Alg, SN%Base64Cert]
     */
    @DataProvider(name = "symmalg-allcert-sn")
    public static Object[][] getAllSymmAlgWithBase64CertAndSN() {
        return DataProviderUtil.getAlgWithBase64CertAndAttr("SN", allcertpath, "all", 0);
    }

    /**
     * 获取所有对称加密算法、证书bankcode
     *
     * @return [bankcode, alg]
     */
    @DataProvider(name = "all-symmalg-bankcode")
    public static Object[][] getAllSymmAlgWithBankCode() {
        return DataProviderUtil.composeCertAttrWithAlg("bankcode", false, true, allcertpath, "all", 0);
    }

    /**
     * 获取所有证书的DN,对称算法为SM4/AES
     *
     * @return [dn, salg]
     */
    @DataProvider(name = "salg-16-alldn")
    public static Object[][] getSAlg16WithCertDN() {
        return DataProviderUtil.composeCertAttrWithAlg("DN", false, true, allcertpath, "all", 16);
    }

    /**
     * 获取所有证书的DN,对称算法为3DES/DES/RC2/RC4
     *
     * @return [dn, salg]
     */
    @DataProvider(name = "salg-8-alldn")
    public static Object[][] getSAlg8WithCertDN() {
        return DataProviderUtil.composeCertAttrWithAlg("DN", false, true, allcertpath, "all", 8);
    }

    /**
     * 获取所有证书的DN,对称算法为3DES/DES/RC2/RC4/SM4/AES
     *
     * @return [dn, salg]
     */
    @DataProvider(name = "salg-0-alldn")
    public static Object[][] getSAlgAllWithCertDN() {
        return DataProviderUtil.composeCertAttrWithAlg("DN", false, true, allcertpath, "all", 0);
    }

    /**
     * 获取所有证书的SN,对称算法为SM4/AES
     *
     * @return [sn, salg]
     */
    @DataProvider(name = "salg-16-allsn")
    public static Object[][] getSAlg16WithCertSN() {
        return DataProviderUtil.composeCertAttrWithAlg("SN", false, true, allcertpath, "all", 16);
    }

    /**
     * 获取所有证书的DN,对称算法为3DES/DES/RC2/RC4/SM4/AES
     *
     * @return [dn, salg]
     */
    @DataProvider(name = "salg-0-allsn")
    public static Object[][] getSAlgAllWithCertSN() {
        return DataProviderUtil.composeCertAttrWithAlg("SN", false, true, allcertpath, "all", 0);
    }

    /**
     * 获取所有证书的bankcode,对称算法为SM4/AES
     *
     * @return [bankcode, salg]
     */
    @DataProvider(name = "salg-16-allbankcode")
    public static Object[][] getSAlg16WithCertBankCode() {
        return DataProviderUtil.composeCertAttrWithAlg("bankcode", false, true, allcertpath, "all", 16);
    }

    /**
     * 获取RSA证书DN及RSA摘要算法、所有对称算法
     *
     * @return [dn, dalg, salg]
     */
    @DataProvider(name = "rsa-dn-dalg-0")
    public static Object[][] rsaCertDNAndDAlgWithAllSAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("dn", true, true, allcertpath, "rsa", 0);
    }

    /**
     * 获取正常RSA证书DN及RSA摘要算法、所有对称算法
     *
     * @return [dn, dalg, salg]
     */
    @DataProvider(name = "normal-rsa-dn-dalg-0")
    public static Object[][] normalRsaCertDN() {
        return DataProviderUtil.composeCertAttrWithAlg("dn", true, true, normalpath, "rsa", 0);
    }

    /**
     * 获取所有证书DN
     *
     * @return [dn]
     */
    @DataProvider(name = "all-cert-dn")
    public static Object[][] allCertDN() {
        return DataProviderUtil.composeCertAttrWithAlg("dn", false, false, allcertpath, "all", 0);
    }

    /**
     * 获取作废RSA证书DN
     *
     * @return [dn]
     */
    @DataProvider(name = "revoke-rsa-dn")
    public static Object[][] revokedRsaCertDN() {
        return DataProviderUtil.composeCertAttrWithAlg("dn", false, false, revokepath, "rsa", 0);
    }

    /**
     * 获取过期RSA证书DN
     *
     * @return [dn]
     */
    @DataProvider(name = "expire-rsa-dn")
    public static Object[][] expireRsaCertDN() {
        return DataProviderUtil.composeCertAttrWithAlg("dn", false, false, expirepath, "rsa", 0);
    }

    /**
     * 获取作不受信任RSA证书DN
     *
     * @return [dn]
     */
    @DataProvider(name = "nottrust-rsa-dn")
    public static Object[][] nottrustRsaCertDN() {
        return DataProviderUtil.composeCertAttrWithAlg("dn", false, false, nottrustpath, "rsa", 0);
    }

    /**
     * 获取正常SM2证书DN及SM2摘要算法、所有对称算法
     *
     * @return [dn, dalg, salg]
     */
    @DataProvider(name = "normal-sm2-dn-dalg-0")
    public static Object[][] normalSm2CertDNAndDAlgWithAllSAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("dn", true, true, normalpath, "sm2", 0);
    }

    /**
     * 获取作废SM2证书DN
     *
     * @return [dn]
     */
    @DataProvider(name = "revoke-sm2-dn")
    public static Object[][] revokedSm2CertDN() {
        return DataProviderUtil.composeCertAttrWithAlg("dn", false, false, revokepath, "sm2", 0);
    }

    /**
     * 获取过期SM2证书DN
     *
     * @return [dn]
     */
    @DataProvider(name = "expire-sm2-dn")
    public static Object[][] expireSm2CertDN() {
        return DataProviderUtil.composeCertAttrWithAlg("dn", false, false, expirepath, "sm2", 0);
    }

    /**
     * 获取正常RSA证书SN及RSA摘要算法、所有对称算法
     *
     * @return [sn, dalg, salg]
     */
    @DataProvider(name = "normal-rsa-sn-dalg-0")
    public static Object[][] normalRsaCertSNAndDAlgWithAllSAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("sn", true, true, normalpath, "rsa", 0);
    }

    /**
     * 获取作废RSA证书SN
     *
     * @return [sn]
     */
    @DataProvider(name = "revoke-rsa-sn")
    public static Object[][] revokedRsaCertSN() {
        return DataProviderUtil.composeCertAttrWithAlg("sn", false, false, revokepath, "rsa", 0);
    }

    /**
     * 获取过期RSA证书SN
     *
     * @return [sn]
     */
    @DataProvider(name = "expire-rsa-sn")
    public static Object[][] expireRsaCertSN() {
        return DataProviderUtil.composeCertAttrWithAlg("sn", false, false, expirepath, "rsa", 0);
    }

    /**
     * 获取作不受信任RSA证书SN
     *
     * @return [sn]
     */
    @DataProvider(name = "nottrust-rsa-sn")
    public static Object[][] nottrustRsaCertSN() {
        return DataProviderUtil.composeCertAttrWithAlg("sn", false, false, nottrustpath, "rsa", 0);
    }

    /**
     * 获取正常SM2证书SN及SM2摘要算法、所有对称算法
     *
     * @return [sn, dalg, salg]
     */
    @DataProvider(name = "normal-sm2-sn-dalg-0")
    public static Object[][] normalSm2CertSNAndDAlgWithAllSAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("sn", true, true, normalpath, "sm2", 0);
    }

    /**
     * 获取作废SM2证书SN
     *
     * @return [sn]
     */
    @DataProvider(name = "revoke-sm2-sn")
    public static Object[][] revokedSm2CertSN() {
        return DataProviderUtil.composeCertAttrWithAlg("sn", false, false, revokepath, "sm2", 0);
    }

    /**
     * 获取过期SM2证书SN
     *
     * @return [sn]
     */
    @DataProvider(name = "expire-sm2-sn")
    public static Object[][] expireSm2CertSN() {
        return DataProviderUtil.composeCertAttrWithAlg("sn", false, false, expirepath, "sm2", 0);
    }

    /**
     * 获取正常RSA证书Bankcode及RSA摘要算法、所有对称算法
     *
     * @return [bankcode, dalg, salg]
     */
    @DataProvider(name = "normal-rsa-bankcode-dalg-0")
    public static Object[][] normalRsaCertBankcode() {
        return DataProviderUtil.composeCertAttrWithAlg("bankcode", true, true, normalpath, "rsa", 0);
    }

    /**
     * 获取作废RSA证书Bankcode
     *
     * @return [bankcode]
     */
    @DataProvider(name = "revoke-rsa-bankcode")
    public static Object[][] revokedRsaCertBankcode() {
        return DataProviderUtil.composeCertAttrWithAlg("bankcode", false, false, revokepath, "rsa", 0);
    }

    /**
     * 获取过期RSA证书Bankcode
     *
     * @return [bankcode]
     */
    @DataProvider(name = "expire-rsa-bankcode")
    public static Object[][] expireRsaCertBankcode() {
        return DataProviderUtil.composeCertAttrWithAlg("bankcode", false, false, expirepath, "rsa", 0);
    }

    /**
     * 获取作不受信任RSA证书Bankcode
     *
     * @return [bankcode]
     */
    @DataProvider(name = "nottrust-rsa-bankcode")
    public static Object[][] nottrustRsaCertBankcode() {
        return DataProviderUtil.composeCertAttrWithAlg("bankcode", false, false, nottrustpath, "rsa", 0);
    }

    /**
     * 获取正常SM2证书Bankcode及SM2摘要算法、所有对称算法
     *
     * @return [bankcode, dalg, salg]
     */
    @DataProvider(name = "normal-sm2-bankcode-dalg-0")
    public static Object[][] normalSm2CertBankcodeAndDAlgWithAllSAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("bankcode", true, true, normalpath, "sm2", 0);
    }

    /**
     * 获取作废SM2证书Bankcode
     *
     * @return [bankcode]
     */
    @DataProvider(name = "revoke-sm2-bankcode")
    public static Object[][] revokedSm2CertBankcode() {
        return DataProviderUtil.composeCertAttrWithAlg("bankcode", false, false, revokepath, "sm2", 0);
    }

    /**
     * 获取过期SM2证书Bankcode
     *
     * @return [bankcode]
     */
    @DataProvider(name = "expire-sm2-bankcode")
    public static Object[][] expireSm2CertBankcode() {
        return DataProviderUtil.composeCertAttrWithAlg("bankcode", false, false, expirepath, "sm2", 0);
    }

    /**
     * 获取SM2证书DN及SM2摘要算法、所有对称算法
     *
     * @return [dn, dalg, salg]
     */
    @DataProvider(name = "sm2-dn-dalg-0")
    public static Object[][] sm2CertDNAndDAlgWithAllSAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("dn", true, true, allcertpath, "sm2", 0);
    }

    /**
     * 获取RSA证书SN及RSA摘要算法、所有对称算法
     *
     * @return [sn, dalg, salg]
     */
    @DataProvider(name = "rsa-sn-dalg-0")
    public static Object[][] rsaCertSNAndDAlgWithAllSAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("sn", true, true, allcertpath, "rsa", 0);
    }

    /**
     * 获取SM2证书SN及SM2摘要算法、所有对称算法
     *
     * @return [sn, dalg, salg]
     */
    @DataProvider(name = "sm2-sn-dalg-0")
    public static Object[][] sm2CertSNAndDAlgWithAllSAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("sn", true, true, allcertpath, "sm2", 0);
    }

    /**
     * 获取RSA证书Bankcode及RSA摘要算法、所有对称算法
     *
     * @return [bankcode, dalg, salg]
     */
    @DataProvider(name = "rsa-bankcode-dalg-0")
    public static Object[][] rsaBankCodeAndDAlgWithAllSAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("bankcode", true, true, allcertpath, "rsa", 0);
    }

    /**
     * 获取SM2证书Bankcode及SM2摘要算法、所有对称算法
     *
     * @return [bankcode, dalg, salg]
     */
    @DataProvider(name = "sm2-bankcode-dalg-0")
    public static Object[][] sm2BankCodeAndDAlgWithAllSAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("bankcode", true, true, allcertpath, "sm2", 0);
    }

    /**
     * 调用数据源,覆盖SM2和RSA所有证书DN和摘要算法
     *
     * @return 【alg，dn】
     */
    @DataProvider(name = "all-alg-dn")
    public static Object[][] AllAlgDN() {
        return DataProviderUtil.resolveAlgDN(allcertpath);
    }

    /**
     * 调用数据源,覆盖SM2和RSA所有证书SN和摘要算法
     *
     * @return 【alg，sn】
     */
    @DataProvider(name = "all-alg-sn")
    public static Object[][] AllAlgSN() {
        return DataProviderUtil.resolveAlgSN(allcertpath);
    }

    /**
     * 调用数据源,覆盖SM2和RSA正常证书SN和摘要算法
     *
     * @return 【alg，sn】
     */
    @DataProvider(name = "normal-alg-sn")
    public static Object[][] NormalAlgSN() {
        return DataProviderUtil.resolveAlgSN(normalpath);
    }

    /**
     * 获取机构代码及摘要,所有证书
     *
     * @return 【alg，bankcode】
     */
    @DataProvider(name = "all-alg-bankcode")
    public static Object[][] allbankCodeAlg() {
        return DataProviderUtil.bankCodeAlg(allcertpath);
    }

    /**
     * 获取SM2和RSA正常证书DN、摘要算法和公钥证书
     *
     * @return 【alg，dn ，cert】
     */
    @DataProvider(name = "normal-alg-dn-cert")
    public static Object[][] normalAlgDNCert() {
        return DataProviderUtil.resolveAlgDNCert(normalpath);
    }

    /**
     * 获取所有证书DN
     *
     * @return 【dn】
     */
    @DataProvider(name = "all-dn")
    public static Object[] allDN() {
        return ParseCert.parseCertByAttributes("DN", allcertpath, "all");
    }

    /**
     * 获取所有证书SN
     *
     * @return 【sn】
     */
    @DataProvider(name = "all-sn")
    public static Object[] allSN() {
        return ParseCert.parseCertByAttributes("SN", allcertpath, "all");
    }

    /**
     * 获取所有证书Bankcode
     *
     * @return 【bankcode】
     */
    @DataProvider(name = "all-bankcode")
    public static Object[] allBankcode() {
        return ParseCert.parseCertByAttributes("bankcode", allcertpath, "all");
    }

    /**
     * 获取SM2和RSA正常证书DN
     *
     * @return 【dn】
     */
    @DataProvider(name = "normal-dn")
    public static Object[] normalDN() {
        return ParseCert.parseCertByAttributes("DN", normalpath, "all");
    }

    /**
     * 获取SM2和RSA正常证书SN
     *
     * @return 【sn】
     */
    @DataProvider(name = "normal-sn")
    public static Object[] normalSN() {
        return ParseCert.parseCertByAttributes("SN", normalpath, "all");
    }

    /**
     * 获取SM2和RSA正常证书Bankcode
     *
     * @return 【bankcode】
     */
    @DataProvider(name = "normal-bankcode")
    public static Object[] normalBankcode() {
        return ParseCert.parseCertByAttributes("bankcode", normalpath, "all");
    }

    /**
     * 获取SM2和RSA作废证书DN
     *
     * @return 【dn】
     */
    @DataProvider(name = "revoke-dn")
    public static Object[] revokeDN() {
        return ParseCert.parseCertByAttributes("DN", revokepath, "all");
    }

    /**
     * 获取SM2和RSA作废证书SN
     *
     * @return 【sn】
     */
    @DataProvider(name = "revoke-sn")
    public static Object[] revokeSN() {
        return ParseCert.parseCertByAttributes("SN", revokepath, "all");
    }

    /**
     * 获取SM2和RSA作废证书Bankcode
     *
     * @return 【bankcode】
     */
    @DataProvider(name = "revoke-bankcode")
    public static Object[] revokeBankcode() {
        return ParseCert.parseCertByAttributes("bankcode", revokepath, "all");
    }

    /**
     * 获取SM2和RSA作废证书DN
     *
     * @return 【dn】
     */
    @DataProvider(name = "expire-dn")
    public static Object[] expireDN() {
        return ParseCert.parseCertByAttributes("DN", expirepath, "all");
    }

    /**
     * 获取SM2和RSA作废证书SN
     *
     * @return 【sn】
     */
    @DataProvider(name = "expire-sn")
    public static Object[] expireSN() {
        return ParseCert.parseCertByAttributes("SN", expirepath, "all");
    }

    /**
     * 获取SM2和RSA作废证书Bankcode
     *
     * @return 【bankcode】
     */
    @DataProvider(name = "expire-bankcode")
    public static Object[] expireBankcode() {
        return ParseCert.parseCertByAttributes("bankcode", expirepath, "all");
    }

    /**
     * 获取正常RSA证书DN及摘要算法
     *
     * @return [dn, alg]
     */
    @DataProvider(name = "normal-rsa-dn-dalg")
    public static Object[][] normalRSACertDNAndAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("dn", true, false, normalpath, "rsa", 0);
    }

    /**
     * 获取作废RSA证书DN及摘要算法
     *
     * @return [dn, alg]
     */
    @DataProvider(name = "revoke-rsa-dn-dalg")
    public static Object[][] revokeRSACertDNAndAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("dn", true, false, revokepath, "rsa", 0);
    }


    /**
     * 获取过期RSA证书DN及摘要算法
     *
     * @return [dn, alg]
     */
    @DataProvider(name = "expire-rsa-dn-dalg")
    public static Object[][] expireRSACertDNAndAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("dn", true, false, expirepath, "rsa", 0);
    }

    /**
     * 获取不受信任RSA证书DN及摘要算法
     *
     * @return [dn, alg]
     */
    @DataProvider(name = "nottrust-rsa-dn-dalg")
    public static Object[][] nottrustRSACertDNAndAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("dn", true, false, nottrustpath, "rsa", 0);
    }

    /**
     * 获取正常RSA证书SN及摘要算法
     *
     * @return [sn, alg]
     */
    @DataProvider(name = "normal-rsa-sn-dalg")
    public static Object[][] normalRSACertSNAndAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("sn", true, false, normalpath, "rsa", 0);
    }

    /**
     * 获取作废RSA证书SN及摘要算法
     *
     * @return [sn, alg]
     */
    @DataProvider(name = "revoke-rsa-sn-dalg")
    public static Object[][] revokeRSACertSNAndAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("sn", true, false, revokepath, "rsa", 0);
    }

    /**
     * 获取过期RSA证书SN及摘要算法
     *
     * @return [sn, alg]
     */
    @DataProvider(name = "expire-rsa-sn-dalg")
    public static Object[][] expireRSACertSNAndAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("sn", true, false, expirepath, "rsa", 0);
    }

    /**
     * 获取不受信任RSA证书SN及摘要算法
     *
     * @return [sn, alg]
     */
    @DataProvider(name = "nottrust-rsa-sn-dalg")
    public static Object[][] nottrustRSACertSNAndAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("sn", true, false, nottrustpath, "rsa", 0);
    }

    /**
     * 获取正常RSA证书Bankcode及摘要算法
     *
     * @return [bankcode, alg]
     */
    @DataProvider(name = "normal-rsa-bankcode-dalg")
    public static Object[][] normalRSACertBankcodeAndAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("bankcode", true, false, normalpath, "rsa", 0);
    }

    /**
     * 获取作废RSA证书Bankcode及摘要算法
     *
     * @return [bankcode, alg]
     */
    @DataProvider(name = "revoke-rsa-bankcode-dalg")
    public static Object[][] revokeRSACertBankcodeAndAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("bankcode", true, false, revokepath, "rsa", 0);
    }

    /**
     * 获取过期RSA证书Bankcode及摘要算法
     *
     * @return [bankcode, alg]
     */
    @DataProvider(name = "expire-rsa-bankcode-dalg")
    public static Object[][] expireRSACertBankcodeAndAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("bankcode", true, false, expirepath, "rsa", 0);
    }

    /**
     * 获取不受信任RSA证书Bankcode及摘要算法
     *
     * @return [bankcode, alg]
     */
    @DataProvider(name = "nottrust-rsa-bankcode-dalg")
    public static Object[][] nottrustRSACertBankcodeAndAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("bankcode", true, false, nottrustpath, "rsa", 0);
    }

    /**
     * 获取正常SM2证书DN及摘要算法
     *
     * @return [dn, alg]
     */
    @DataProvider(name = "normal-sm2-dn-dalg")
    public static Object[][] normalSM2CertDNAndAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("dn", true, false, normalpath, "sm2", 0);
    }

    /**
     * 获取作废SM2证书DN及摘要算法
     *
     * @return [dn, alg]
     */
    @DataProvider(name = "revoke-sm2-dn-dalg")
    public static Object[][] revokeSM2CertDNAndAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("dn", true, false, revokepath, "sm2", 0);
    }

    /**
     * 获取过期SM2证书DN及摘要算法
     *
     * @return [dn, alg]
     */
    @DataProvider(name = "expire-sm2-dn-dalg")
    public static Object[][] expireSM2CertDNAndAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("dn", true, false, expirepath, "sm2", 0);
    }

    /**
     * 获取不受信任SM2证书DN及摘要算法
     *
     * @return [dn, alg]
     */
    @DataProvider(name = "nottrust-sm2-dn-dalg")
    public static Object[][] nottrustSM2CertDNAndAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("dn", true, false, nottrustpath, "sm2", 0);
    }

    /**
     * 获取正常SM2证书SN及摘要算法
     *
     * @return [sn, alg]
     */
    @DataProvider(name = "normal-sm2-sn-dalg")
    public static Object[][] normalSM2CertSNAndAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("sn", true, false, normalpath, "sm2", 0);
    }

    /**
     * 获取作废SM2证书SN及摘要算法
     *
     * @return [sn, alg]
     */
    @DataProvider(name = "revoke-sm2-sn-dalg")
    public static Object[][] revokeSM2CertSNAndAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("sn", true, false, revokepath, "sm2", 0);
    }

    /**
     * 获取过期SM2证书SN及摘要算法
     *
     * @return [sn, alg]
     */
    @DataProvider(name = "expire-sm2-sn-dalg")
    public static Object[][] expireSM2CertSNAndAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("sn", true, false, expirepath, "sm2", 0);
    }

    /**
     * 获取不受信任SM2证书SN及摘要算法
     *
     * @return [sn, alg]
     */
    @DataProvider(name = "nottrust-sm2-sn-dalg")
    public static Object[][] nottrustSM2CertSNAndAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("sn", true, false, nottrustpath, "sm2", 0);
    }

    /**
     * 获取正常SM2证书Bankcode及摘要算法
     *
     * @return [bankcode, alg]
     */
    @DataProvider(name = "normal-sm2-bankcode-dalg")
    public static Object[][] normalSM2CertBankcodeAndAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("bankcode", true, false, normalpath, "sm2", 0);
    }

    /**
     * 获取作废SM2证书Bankcode及摘要算法
     *
     * @return [bankcode, alg]
     */
    @DataProvider(name = "revoke-sm2-bankcode-dalg")
    public static Object[][] revokeSM2CertBankcodeAndAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("bankcode", true, false, revokepath, "sm2", 0);
    }

    /**
     * 获取过期SM2证书Bankcode及摘要算法
     *
     * @return [bankcode, alg]
     */
    @DataProvider(name = "expire-sm2-bankcode-dalg")
    public static Object[][] expireSM2CertBankcodeAndAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("bankcode", true, false, expirepath, "sm2", 0);
    }

    /**
     * 获取不受信任SM2证书Bankcode及摘要算法
     *
     * @return [bankcode, alg]
     */
    @DataProvider(name = "nottrust-sm2-bankcode-dalg")
    public static Object[][] nottrustSM2CertBankcodeAndAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("bankcode", true, false, nottrustpath, "sm2", 0);
    }

    /**
     * 获取正常RSA证书实体
     *
     * @return x509Cert
     */
    @DataProvider(name = "normal-rsa-cert")
    public static Object[] normalRSACert() {
        return DataProviderUtil.getCert(normalpath, "rsa");
    }

    /**
     * 获取过期RSA证书实体
     *
     * @return x509Cert
     */
    @DataProvider(name = "expire-rsa-cert")
    public static Object[] expireRSACert() {
        return DataProviderUtil.getCert(expirepath, "rsa");
    }

    /**
     * 获取作废RSA证书实体
     *
     * @return x509Cert
     */
    @DataProvider(name = "revoke-rsa-cert")
    public static Object[] revokeRSACert() {
        return DataProviderUtil.getCert(revokepath, "rsa");
    }

    /**
     * 获取正常SM2证书实体
     *
     * @return x509Cert
     */
    @DataProvider(name = "normal-sm2-cert")
    public static Object[] normalSM2Cert() {
        return DataProviderUtil.getCert(normalpath, "sm2");
    }

    /**
     * 获取过期SM2证书实体
     *
     * @return x509Cert
     */
    @DataProvider(name = "expire-sm2-cert")
    public static Object[] expireSM2Cert() {
        return DataProviderUtil.getCert(expirepath, "sm2");
    }

    /**
     * 获取作废SM2证书实体
     *
     * @return x509Cert
     */
    @DataProvider(name = "revoke-sm2-cert")
    public static Object[] revokeSM2Cert() {
        return DataProviderUtil.getCert(revokepath, "sm2");
    }

    /**
     * 获取正常RSA证书DN、Base64信息以及摘要算法
     * @return [dn%base64Cert,dalg]
     */
    @DataProvider(name = "normal-rsa-dn-base64-dalg")
    public static Object[][] normalRSABase64CertAndDNWithDAlg(){
        return DataProviderUtil.getBase64CertAndAttrWithDAlg("DN",normalpath,"rsa");
    }
    /**
     * 获取过期RSA证书DN、Base64信息以及摘要算法
     * @return [dn%base64Cert,dalg]
     */
    @DataProvider(name = "expire-rsa-dn-base64-dalg")
    public static Object[][] expireRSABase64CertAndDNWithDAlg(){
        return DataProviderUtil.getBase64CertAndAttrWithDAlg("DN",expirepath,"rsa");
    }
    /**
     * 获取作废RSA证书DN、Base64信息以及摘要算法
     * @return [dn%base64Cert,dalg]
     */
    @DataProvider(name = "revoke-rsa-dn-base64-dalg")
    public static Object[][] revokeRSABase64CertAndDNWithDAlg(){
        return DataProviderUtil.getBase64CertAndAttrWithDAlg("DN",revokepath,"rsa");
    }
    /**
     * 获取不受信任RSA证书DN、Base64信息以及摘要算法
     * @return [dn%base64Cert,dalg]
     */
    @DataProvider(name = "nottrust-rsa-dn-base64-dalg")
    public static Object[][] nottrustRSABase64CertAndDNWithDAlg(){
        return DataProviderUtil.getBase64CertAndAttrWithDAlg("DN",nottrustpath,"rsa");
    }

    /**
     * 获取正常RSA证书SN、Base64信息以及摘要算法
     * @return [sn%base64Cert,dalg]
     */
    @DataProvider(name = "normal-rsa-sn-base64-dalg")
    public static Object[][] normalRSABase64CertAndSNWithDAlg(){
        return DataProviderUtil.getBase64CertAndAttrWithDAlg("SN",normalpath,"rsa");
    }
    /**
     * 获取过期RSA证书SN、Base64信息以及摘要算法
     * @return [sn%base64Cert,dalg]
     */
    @DataProvider(name = "expire-rsa-sn-base64-dalg")
    public static Object[][] expireRSABase64CertAndSNWithDAlg(){
        return DataProviderUtil.getBase64CertAndAttrWithDAlg("SN",expirepath,"rsa");
    }
    /**
     * 获取作废RSA证书SN、Base64信息以及摘要算法
     * @return [sn%base64Cert,dalg]
     */
    @DataProvider(name = "revoke-rsa-sn-base64-dalg")
    public static Object[][] revokeRSABase64CertAndSNWithDAlg(){
        return DataProviderUtil.getBase64CertAndAttrWithDAlg("SN",revokepath,"rsa");
    }
    /**
     * 获取不受信任RSA证书SN、Base64信息以及摘要算法
     * @return [sn%base64Cert,dalg]
     */
    @DataProvider(name = "nottrust-rsa-sn-base64-dalg")
    public static Object[][] nottrustRSABase64CertAndSNWithDAlg(){
        return DataProviderUtil.getBase64CertAndAttrWithDAlg("SN",nottrustpath,"rsa");
    }

    /**
     * 获取正常SM2证书DN、Base64信息以及摘要算法
     * @return [dn%base64Cert,dalg]
     */
    @DataProvider(name = "normal-sm2-dn-base64-dalg")
    public static Object[][] normalSM2Base64CertAndDNWithDAlg(){
        return DataProviderUtil.getBase64CertAndAttrWithDAlg("DN",normalpath,"sm2");
    }
    /**
     * 获取过期SM2证书DN、Base64信息以及摘要算法
     * @return [dn%base64Cert,dalg]
     */
    @DataProvider(name = "expire-sm2-dn-base64-dalg")
    public static Object[][] expireSM2Base64CertAndDNWithDAlg(){
        return DataProviderUtil.getBase64CertAndAttrWithDAlg("DN",expirepath,"sm2");
    }
    /**
     * 获取作废SM2证书DN、Base64信息以及摘要算法
     * @return [dn%base64Cert,dalg]
     */
    @DataProvider(name = "revoke-sm2-dn-base64-dalg")
    public static Object[][] revokeSM2Base64CertAndDNWithDAlg(){
        return DataProviderUtil.getBase64CertAndAttrWithDAlg("DN",revokepath,"sm2");
    }
    /**
     * 获取不受信任SM2证书DN、Base64信息以及摘要算法
     * @return [dn%base64Cert,dalg]
     */
    @DataProvider(name = "nottrust-sm2-dn-base64-dalg")
    public static Object[][] nottrustSM2Base64CertAndDNWithDAlg(){
        return DataProviderUtil.getBase64CertAndAttrWithDAlg("DN",nottrustpath,"sm2");
    }

    /**
     * 获取正常SM2证书SN、Base64信息以及摘要算法
     * @return [sn%base64Cert,dalg]
     */
    @DataProvider(name = "normal-sm2-sn-base64-dalg")
    public static Object[][] normalSM2Base64CertAndSNWithDAlg(){
        return DataProviderUtil.getBase64CertAndAttrWithDAlg("SN",normalpath,"sm2");
    }
    /**
     * 获取过期SM2证书SN、Base64信息以及摘要算法
     * @return [sn%base64Cert,dalg]
     */
    @DataProvider(name = "expire-sm2-sn-base64-dalg")
    public static Object[][] expireSM2Base64CertAndSNWithDAlg(){
        return DataProviderUtil.getBase64CertAndAttrWithDAlg("SN",expirepath,"sm2");
    }
    /**
     * 获取作废SM2证书SN、Base64信息以及摘要算法
     * @return [sn%base64Cert,dalg]
     */
    @DataProvider(name = "revoke-sm2-sn-base64-dalg")
    public static Object[][] revokeSM2Base64CertAndSNWithDAlg(){
        return DataProviderUtil.getBase64CertAndAttrWithDAlg("SN",revokepath,"sm2");
    }
    /**
     * 获取不受信任SM2证书SN、Base64信息以及摘要算法
     * @return [sn%base64Cert,dalg]
     */
    @DataProvider(name = "nottrust-sm2-sn-base64-dalg")
    public static Object[][] nottrustSM2Base64CertAndSNWithDAlg(){
        return DataProviderUtil.getBase64CertAndAttrWithDAlg("SN",nottrustpath,"sm2");
    }

}
