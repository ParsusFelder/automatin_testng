package qa.infosec.testng.netsign.dataprovider;

import cn.com.infosec.jce.provider.InfosecProvider;
import org.testng.annotations.DataProvider;
import qa.infosec.testng.netsign.dataprovider.util.ParameterUtil;
import qa.infosec.testng.netsign.dataprovider.util.ParseCert;
import qa.infosec.testng.netsign.dataprovider.util.ParseFile;
import qa.infosec.testng.netsign.dataprovider.DataProviderUtil;

import java.security.Security;

/**
 * ����Դ
 * <p>Title: NetSignDataProvider</p>
 * <p>Description: </p>
 *
 * @author zhaoyz
 * @date 2019��8��15��
 */
public class NetSignDataProvider {

    static {
        Security.addProvider(new InfosecProvider());
    }

    /**
     * ��������Դ,����SM2��RSA����֤��,����֤��
     *
     * @return ��alg��dn��
     */
    @DataProvider(name = "normal-alg-dn")
    public static Object[][] normalAlgDN() {
        return DataProviderUtil.resolveAlgDN(ParameterUtil.normalpath);
    }

    /**
     * ��������Դ,����SM2��RSA����֤��,����֤��
     *
     * @return ��alg��dn��
     */
    @DataProvider(name = "expire-alg-dn")
    public static Object[][] expireAlgDN() {
        return DataProviderUtil.resolveAlgDN(ParameterUtil.expirepath);
    }

    /**
     * ��������Դ,����SM2��RSA����֤��,����֤��
     *
     * @return ��alg��dn��
     */
    @DataProvider(name = "revoke-alg-dn")
    public static Object[][] revokeAlgDN() {
        return DataProviderUtil.resolveAlgDN(ParameterUtil.revokepath);
    }

    /**
     * ��������Դ,����SM2��RSA����֤��,��������֤��
     *
     * @return ��alg��dn��
     */
    @DataProvider(name = "nottrust-alg-dn")
    public static Object[][] nottrustAlgDN() {
        return DataProviderUtil.resolveAlgDN(ParameterUtil.nottrustpath);
    }

    /**
     * ��������Դ,����SM2��RSA����֤��,������֤��
     *
     * @return ��alg��dn��
     */
    @DataProvider(name = "blacklist-alg-dn")
    public static Object[][] blacklistAlgDN() {
        return DataProviderUtil.resolveAlgDN(ParameterUtil.blacklistpath);
    }

    /**
     * ��ȡ�������뼰ժҪ,��Ӧ����֤��
     *
     * @return ��alg��bankcode��
     */
    @DataProvider(name = "normal-alg-bankcode")
    public static Object[][] normalbankCodeAlg() {
        return DataProviderUtil.bankCodeAlg(ParameterUtil.normalpath);
    }

    /**
     * ��ȡ�������뼰ժҪ,��Ӧ����֤��
     *
     * @return ��alg��bankcode��
     */
    @DataProvider(name = "expire-alg-bankcode")
    public static Object[][] expirebankCodeAlg() {
        return DataProviderUtil.bankCodeAlg(ParameterUtil.expirepath);
    }

    /**
     * ��ȡ�������뼰ժҪ,��Ӧ����֤��
     *
     * @return ��alg��bankcode��
     */
    @DataProvider(name = "revoke-alg-bankcode")
    public static Object[][] revokebankCodeAlg() {
        return DataProviderUtil.bankCodeAlg(ParameterUtil.revokepath);
    }

    /**
     * ��ȡ�������뼰ժҪ,��Ӧ��������֤��
     *
     * @return ��alg��bankcode��
     */
    @DataProvider(name = "nottrust-alg-bankcode")
    public static Object[][] nottrustbankCodeAlg() {
        return DataProviderUtil.bankCodeAlg(ParameterUtil.nottrustpath);
    }

    /**
     * ��ȡ�������뼰ժҪ,��Ӧ������֤��
     *
     * @return ��alg��bankcode��
     */
    @DataProvider(name = "blacklist-alg-bankcode")
    public static Object[][] blacklistbankCodeAlg() {
        return DataProviderUtil.bankCodeAlg(ParameterUtil.blacklistpath);
    }

    /**
     * ������ JSON�ַ�����������ͨ���ױ���
     *
     * @return ��json��
     */
    @DataProvider(name = "normal-json")
    public static Object[] jsonData() {
        return DataProviderUtil.JsonDataList();
    }

    /**
     * ������ JSON�ַ��������ܹ�����Կ����,����֤��
     *
     * @return ��encdn��json��
     */
    @DataProvider(name = "normal-dn-json")
    public static Object[][] normalJsonKeyTextDN() {
        return DataProviderUtil.keyTextWithDN(ParameterUtil.normalpath);
    }

    /**
     * ������ JSON�ַ��������ܹ�����Կ����,����֤��
     *
     * @return ��encdn��json��
     */
    @DataProvider(name = "expire-dn-json")
    public static Object[][] expireJsonKeyTextDN() {
        return DataProviderUtil.keyTextWithDN(ParameterUtil.expirepath);
    }

    /**
     * ������ JSON�ַ��������ܹ�����Կ����,����֤��
     *
     * @return ��encdn��json��
     */
    @DataProvider(name = "revoke-dn-json")
    public static Object[][] revokeJsonKeyTextDN() {
        return DataProviderUtil.keyTextWithDN(ParameterUtil.revokepath);
    }

    /**
     * ������ JSON�ַ��������ܹ�����Կ����,��������֤��
     *
     * @return ��encdn��json��
     */
    @DataProvider(name = "nottrust-dn-json")
    public static Object[][] nottrustJsonKeyTextDN() {
        return DataProviderUtil.keyTextWithDN(ParameterUtil.nottrustpath);
    }

    /**
     * ������ JSON�ַ��������ܹ�����Կ����,������֤��
     *
     * @return ��encdn��json��
     */
    @DataProvider(name = "blacklist-dn-json")
    public static Object[][] blacklistJsonKeyTextDN() {
        return DataProviderUtil.keyTextWithDN(ParameterUtil.blacklistpath);
    }

    /**
     * ������ JSON�ַ��������ܼ�ǩ�����ģ�����֤��
     *
     * @return ��json��signdn, encdn��
     */
    @DataProvider(name = "normal-json-signdn-encdn")
    public static Object[][] normalJsonSignDNAndEncryDN() {
        return DataProviderUtil.jsonSignDNAndEncryDN(ParameterUtil.normalpath);
    }

    /**
     * ������ JSON�ַ��������ܼ�ǩ�����ģ�����֤��
     *
     * @return ��json��signdn, encdn��
     */
    @DataProvider(name = "expire-json-signdn-encdn")
    public static Object[][] expireJsonSignDNAndEncryDN() {
        return DataProviderUtil.jsonSignDNAndEncryDN(ParameterUtil.expirepath);
    }

    /**
     * ������ JSON�ַ��������ܼ�ǩ�����ģ�����֤��
     *
     * @return ��json��signdn, encdn��
     */
    @DataProvider(name = "revoke-json-signdn-encdn")
    public static Object[][] revokeJsonSignDNAndEncryDN() {
        return DataProviderUtil.jsonSignDNAndEncryDN(ParameterUtil.revokepath);
    }

    /**
     * ������ JSON�ַ��������ܼ�ǩ�����ģ���������֤��
     *
     * @return ��json��signdn, encdn��
     */
    @DataProvider(name = "nottrust-json-signdn-encdn")
    public static Object[][] nottrustJsonSignDNAndEncryDN() {
        return DataProviderUtil.jsonSignDNAndEncryDN(ParameterUtil.nottrustpath);
    }

    /**
     * ������ JSON�ַ��������ܼ�ǩ�����ģ�������֤��
     *
     * @return ��json��signdn, encdn��
     */
    @DataProvider(name = "blacklist-json-signdn-encdn")
    public static Object[][] blacklistJsonSignDNAndEncryDN() {
        return DataProviderUtil.jsonSignDNAndEncryDN(ParameterUtil.blacklistpath);
    }

    /**
     * ������ JSON�ַ��������ܼ�ǩ�����ģ�����֤���Ӧ�к�
     *
     * @return ��json��signbank, encbank��
     */
    @DataProvider(name = "normal-json-signbank-encbank")
    public static Object[][] normalJsonSignAndEncryBank() {
        return DataProviderUtil.jsonSignAndEncryBank(ParameterUtil.normalpath);
    }

    /**
     * ������ JSON�ַ��������ܼ�ǩ�����ģ�����֤���Ӧ�к�
     *
     * @return ��json��signbank, encbank��
     */
    @DataProvider(name = "expire-json-signbank-encbank")
    public static Object[][] expireJsonSignAndEncryBank() {
        return DataProviderUtil.jsonSignAndEncryBank(ParameterUtil.expirepath);
    }

    /**
     * ������ JSON�ַ��������ܼ�ǩ�����ģ�����֤���Ӧ�к�
     *
     * @return ��json��signbank, encbank��
     */
    @DataProvider(name = "revoke-json-signbank-encbank")
    public static Object[][] revokeJsonSignAndEncryBank() {
        return DataProviderUtil.jsonSignAndEncryBank(ParameterUtil.revokepath);
    }

    /**
     * ������ JSON�ַ��������ܼ�ǩ�����ģ���������֤���Ӧ�к�
     *
     * @return ��json��signbank, encbank��
     */
    @DataProvider(name = "nottrust-json-signbank-encbank")
    public static Object[][] nottrustJsonSignAndEncryBank() {
        return DataProviderUtil.jsonSignAndEncryBank(ParameterUtil.nottrustpath);
    }

    /**
     * ������ JSON�ַ��������ܼ�ǩ�����ģ�������֤���Ӧ�к�
     *
     * @return ��json��signbank, encbank��
     */
    @DataProvider(name = "blacklist-json-signbank-encbank")
    public static Object[][] blacklistJsonSignAndEncryBank() {
        return DataProviderUtil.jsonSignAndEncryBank(ParameterUtil.blacklistpath);
    }

    /**
     * ��ȡ��Կ�б���RSA֤������
     *
     * @return ��dn��
     */
    @DataProvider(name = "rsakeystore-dn")
    public static Object[] getRSAKeystoreDN() {
        return DataProviderUtil.getRSAKeystoreDN();
    }

    /**
     * ��ȡ��Կ�б��й���֤������
     *
     * @return ��dn��
     */
    @DataProvider(name = "sm2keystore-dn")
    public static Object[] getSM2KeystoreDN() {
        return DataProviderUtil.getSM2KeystoreDN();
    }

    /**
     * ��ȡ��Կ�б�������֤������
     *
     * @return ��dn��
     */
    @DataProvider(name = "keystore-dn")
    public static Object[] getKeystoreDN() {
        return DataProviderUtil.getKeystoreDN();
    }

    /**
     * ֻ��ȡrsa֤��ʵ��
     *
     * @return ��X509Certificate cert��
     */
    @DataProvider(name = "rsa-cert")
    public static Object[] getRsaCert() {
        return DataProviderUtil.getCert(ParameterUtil.normalpath, "rsa");
    }

    /**
     * ֻ��ȡsm2֤��ʵ��
     *
     * @return ��X509Certificate cert��
     */
    @DataProvider(name = "sm2-cert")
    public static Object[] getSM2Cert() {
        return DataProviderUtil.getCert(ParameterUtil.normalpath, "sm2");
    }

    /**
     * ��ȡrsa��sm2֤��ʵ��
     *
     * @return ��X509Certificate cert��
     */
    @DataProvider(name = "normal-cert")
    public static Object[] getCert() {
        return DataProviderUtil.getCert(ParameterUtil.normalpath, "all");
    }

    /**
     * ��ȡrsa��sm2ժҪ�㷨
     */
    @DataProvider(name = "alg")
    public static Object[] getAlg() {
        return DataProviderUtil.getAlg();
    }

    /**
     * ��ȡrsaժҪ�㷨
     */
    @DataProvider(name = "rsa-alg")
    public static Object[] getRsaAlg() {
        return DataProviderUtil.RSAHashArrays();
    }
//===========================================facePayment1.3����======================================================

    /**
     * ����Ϊnull��""
     *
     * @return ��String��
     */
    @DataProvider(name = "emptys-parameter")
    public static Object[] Emptys() {
        return DataProviderUtil.Emptys();
    }

    /**
     * ��ȡ�Գ��㷨����
     * return��symmAlg��
     */
    @DataProvider(name = "symmAlg")
    public static Object[] getSymmetricalAlg() {
        return DataProviderUtil.getSymmetricalAlg(0);
    }

    /**
     * ��ȡ�Գ��㷨���ͼ��Գ���Կ
     * ivlength = 0 �����������ͶԳ���Կ���㷨
     * ivlength = 8 ��������Ϊ3DES/DES/RC4/RC2�Գ���Կ���㷨
     * ivlength = 16 ��������ΪAES/SM4�Գ���Կ���㷨
     * ivEmpty = false �����������ģʽ
     */
    @DataProvider(name = "symmKey-all-alg")
    public static Object[] getSymmKeyAndAlg() {
        return DataProviderUtil.getSymmKeyAndAlg(0, false);
    }

    /**
     * ��ȡ�Գ��㷨���ͼ��Գ���Կ
     * ivlength = 0 �����������ͶԳ���Կ���㷨
     * ivlength = 8 ��������Ϊ3DES/DES/RC4/RC2�Գ���Կ���㷨
     * ivlength = 16 ��������ΪAES/SM4�Գ���Կ���㷨
     * ivEmpty = true �����غ���/ECB�����ģʽ��RC4/RC2�Գ���Կ�㷨
     */
    @DataProvider(name = "symmKey-all-alg-ivEmpty")
    public static Object[] getSymmKeyAndAlgIVEmpty() {
        return DataProviderUtil.getSymmKeyAndAlg(0, true);
    }

    /**
     * ��ȡ�Գ��㷨���͡��Գ���Կ�����ģʽ
     * ivlength = 0 �����������ͶԳ���Կ���㷨
     *
     * @return ��symmKeyAlg,modePadding��
     */
    @DataProvider(name = "symmKeyAlg-all-modepadding")
    public static Object[][] SymmKeyAllAndModePadding() {
        return DataProviderUtil.symmKeyAndModePadding(0, false);
    }

    /**
     * ��ȡ�Գ��㷨���͡��Գ���Կ�����ģʽ
     * ivlength = 8 ��������Ϊ3DES/DES/RC4/RC2�Գ���Կ���㷨
     *
     * @return ��symmKeyAlg,modePadding��
     */
    @DataProvider(name = "symmKeyAlg-8-modepadding")
    public static Object[][] SymmKeyDESor3DESAndModePadding() {
        return DataProviderUtil.symmKeyAndModePadding(8, false);
    }

    /**
     * ��ȡ�Գ��㷨���͡��Գ���Կ�����ģʽ
     * ivlength = 16 ��������ΪAES/SM4�Գ���Կ���㷨
     *
     * @return ��symmKeyAlg,modePadding��
     */
    @DataProvider(name = "symmKeyAlg-16-modepadding")
    public static Object[][] SymmKeySM4orAESAndModePadding() {
        return DataProviderUtil.symmKeyAndModePadding(16, false);
    }

    /**
     * ��ȡ�Գ��㷨���͡��Գ���Կ�����ģʽ
     * ivlength = 0 �����������ͶԳ���Կ���㷨
     * ivEmpty = true �����غ���/ECB�����ģʽ��RC4/RC2�Գ���Կ�㷨
     *
     * @return ��symmKeyAlg,modePadding��
     */
    @DataProvider(name = "symmKeyAlg-all-modepadding-ivEmpty")
    public static Object[][] SymmKeyAllAndModePaddingIVEmpty() {
        return DataProviderUtil.symmKeyAndModePadding(0, true);
    }

    /**
     * ��ȡ�Գ��㷨���͡��Գ���Կ�����ģʽ
     * ivlength = 8 ��������Ϊ3DES/DES/RC4/RC2�Գ���Կ���㷨
     * ivEmpty = true �����غ���/ECB�����ģʽ��RC4/RC2�Գ���Կ�㷨
     *
     * @return ��symmKeyAlg,modePadding��
     */
    @DataProvider(name = "symmKeyAlg-8-modepadding-ivEmpty")
    public static Object[][] SymmKey3DESorDESAndModePaddingIVEmpty() {
        return DataProviderUtil.symmKeyAndModePadding(8, true);
    }

    /**
     * ��ȡ�Գ��㷨���͡��Գ���Կ�����ģʽ
     * ivlength = 16 ��������ΪAES/SM4�Գ���Կ���㷨
     * ivEmpty = true �����غ���/ECB�����ģʽ��RC4/RC2�Գ���Կ�㷨
     *
     * @return ��symmKeyAlg,modePadding��
     */
    @DataProvider(name = "symmKeyAlg-16-modepadding-ivEmpty")
    public static Object[][] SymmKeySM4orAESAndModePaddingIVEmpty() {
        return DataProviderUtil.symmKeyAndModePadding(16, true);
    }

    /**
     * ����symmkey.xml��ȡ�Գ���Կ�š����͡�����
     * ivlength = 0 �Գ���Կ����ΪSM4/AES/3DES/DES�Գ���Կ���㷨
     *
     * @return ��keylable&type&data��
     */
    @DataProvider(name = "keylable-type-data-0")
    public static Object[] SKeyLableAndTypeAndDataALL() {
        return DataProviderUtil.getKeyLbAndTpAndData(0);
    }

    /**
     * ����symmkey.xml��ȡ�Գ���Կ�š����͡�����
     * ivlength = 8 �Գ���Կ����Ϊ3DES/DES�Գ���Կ���㷨
     *
     * @return ��keylable&type&data��
     */
    @DataProvider(name = "keylable-type-data-8")
    public static Object[] SKeyLableAndTypeAndDataIv8() {
        return DataProviderUtil.getKeyLbAndTpAndData(8);
    }

    /**
     * ����symmkey.xml��ȡ�Գ���Կ�š����͡�����
     * ivlength = 16 �Գ���Կ����ΪSM4/AES�Գ���Կ���㷨
     *
     * @return ��keylable&type&data��
     */
    @DataProvider(name = "keylable-type-data-16")
    public static Object[] SKeyLableAndTypeAndDataIv16() {
        return DataProviderUtil.getKeyLbAndTpAndData(16);
    }

    /**
     * ��ȡ�Գ���Կ�����ģʽ���Գ���Կ����keyLable/keyType/keyData
     * ivEmpty = true �������ģʽ������/ECB
     * ivlength = 16 �Գ���Կ����ΪSM4/AES�Գ���Կ���㷨
     *
     * @return ��keylable&type&data,modeAndPadding��
     */
    @DataProvider(name = "keylable-type-data-16-modepadding")
    public static Object[][] SymmkeyIv16AndModePadding() {
        return DataProviderUtil.symmKeyWithModePadding(16, true);
    }

    /**
     * ��ȡ�Գ���Կ�����ģʽ���Գ���Կ����keyLable/keyType/keyData
     * ivEmpty = true �������ģʽ������/ECB
     * ivlength = 8 �Գ���Կ����ΪDES/3DES�Գ���Կ���㷨
     *
     * @return ��keylable&type&data,modeAndPadding��
     */
    @DataProvider(name = "keylable-type-data-8-modepadding")
    public static Object[][] SymmkeyIv8AndModePadding() {
        return DataProviderUtil.symmKeyWithModePadding(8, true);
    }

    /**
     * ��ȡ�Գ���Կ�����ģʽ���Գ���Կ����keyLable/keyType/keyData
     * ivEmpty = true �������ģʽ������/ECB
     * ivlength = 8 �Գ���Կ����ΪDES/3DES�Գ���Կ���㷨
     *
     * @return ��keylable&type&data,modeAndPadding��
     */
    @DataProvider(name = "keylable-type-data-0-modepadding")
    public static Object[][] SymmkeyAllAndModePadding() {
        return DataProviderUtil.symmKeyWithModePadding(0, true);
    }

    /**
     * ��ȡ�Գ���Կ�㷨���ͣ����ģʽ
     * ivEmpty = true �������ģʽ������/ECB
     * ivlength = 8 �Գ���Կ����ΪDES/3DES�Գ���Կ���㷨
     */
    @DataProvider(name = "alg-8-modepadding")
    public static Object[][] AlgAndModePaddingIv8() {
        return DataProviderUtil.AlgWithModePadding(8, true);
    }

    /**
     * ��ȡ�Գ���Կ�㷨���ͣ����ģʽ
     * ivEmpty = true �������ģʽ������/ECB
     * ivlength = 16 �Գ���Կ����ΪAES/SM4�Գ���Կ���㷨
     */
    @DataProvider(name = "alg-16-modepadding")
    public static Object[][] AlgAndModePaddingIv16() {
        return DataProviderUtil.AlgWithModePadding(16, true);
    }

    /**
     * ��ȡ�Գ���Կ�㷨���ͣ����ģʽ
     * ivEmpty = true �������ģʽ������/ECB
     * ivlength = 0 �Գ���Կ����ΪAES/SM4/DES/3DES�Գ���Կ���㷨
     */
    @DataProvider(name = "alg-all-modepadding")
    public static Object[][] AlgAndModePaddingAll() {
        return DataProviderUtil.AlgWithModePadding(0, true);
    }

    /**
     * ��ȡ�Գ���Կ�Լ�֤��DN
     * ivlength = 8 �Գ���Կ����ΪDES/3DES�Գ���Կ���㷨
     */
    @DataProvider(name = "symmkey-8-dn")
    public static Object[][] SymmKeyIv8AndDN() {
        return DataProviderUtil.symmKeyWithDN(8);
    }

    /**
     * ��ȡ�Գ���Կ�Լ�֤��DN
     * ivlength = 8 �Գ���Կ����ΪSM4/AES�Գ���Կ���㷨
     */
    @DataProvider(name = "symmkey-16-dn")
    public static Object[][] SymmKeyIv16AndDN() {
        return DataProviderUtil.symmKeyWithDN(16);
    }

    /**
     * ��ȡ�Գ���Կ�Լ�֤��DN
     * ivlength = 0 �Գ���Կ����ΪSM4/AES/DES/3DES�Գ���Կ���㷨
     */
    @DataProvider(name = "symmkey-0-dn")
    public static Object[][] SymmKeyAllAndDN() {
        return DataProviderUtil.symmKeyWithDN(0);
    }
//===========================================facePayment1.6����======================================================

    /**
     * ��ȡ�ǶԳ����ģʽ��֤��DN
     *
     * @return ��modeAndpadding,dn��
     */
    @DataProvider(name = "modepadding-dn")
    public static Object[][] AsymmModeAndPaddingWithDN() {
        return DataProviderUtil.asymmModeAndPaddingWithDN();
    }
//===========================================bcm1.1����==============================================================

    /**
     * ��ȡ����RSA֤��DN��ժҪ�㷨
     *
     * @return [dn, alg]
     */
    @DataProvider(name = "rsadn-normal-alg")
    public static Object[][] RSANormalCertDNAndAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("DN", true, false, ParameterUtil.normalpath, "rsa", 0);
    }

    /**
     * ��ȡ����RSA֤��DN��ժҪ�㷨
     *
     * @return [dn, alg]
     */
    @DataProvider(name = "rsadn-expire-alg")
    public static Object[][] RSAExpireCertDNAndAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("DN", true, false, ParameterUtil.expirepath, "rsa", 0);
    }

    /**
     * ��ȡ����RSA֤��DN��ժҪ�㷨
     *
     * @return [dn, alg]
     */
    @DataProvider(name = "rsadn-revoke-alg")
    public static Object[][] RSARevokeCertDNAndAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("DN", true, false, ParameterUtil.revokepath, "rsa", 0);
    }

    /**
     * ��ȡ��������RSA֤��DN��ժҪ�㷨
     *
     * @return [dn, alg]
     */
    @DataProvider(name = "rsadn-nottrust-alg")
    public static Object[][] RSANottrustCertDNAndAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("DN", true, false, ParameterUtil.nottrustpath, "rsa", 0);
    }

    /**
     * ��ȡ����SM2֤��DN��ժҪ�㷨
     *
     * @return [dn, alg]
     */
    @DataProvider(name = "sm2dn-normal-alg")
    public static Object[][] SM2NormalCertDNAndAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("DN", true, false, ParameterUtil.normalpath, "sm2", 0);
    }

    /**
     * ��ȡ����SM2֤��DN��ժҪ�㷨
     *
     * @return [dn, alg]
     */
    @DataProvider(name = "sm2dn-expire-alg")
    public static Object[][] SM2ExpireCertDNAndAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("DN", true, false, ParameterUtil.expirepath, "sm2", 0);
    }

    /**
     * ��ȡ����SM2֤��DN��ժҪ�㷨
     *
     * @return [dn, alg]
     */
    @DataProvider(name = "sm2dn-revoke-alg")
    public static Object[][] SM2RevokeCertDNAndAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("DN", true, false, ParameterUtil.revokepath, "sm2", 0);
    }

    /**
     * ��ȡ��������SM2֤��DN��ժҪ�㷨
     *
     * @return [dn, alg]
     */
    @DataProvider(name = "sm2dn-nottrust-alg")
    public static Object[][] SM2NottrustCertDNAndAlg() {
        return DataProviderUtil.composeCertAttrWithAlg("DN", true, false, ParameterUtil.nottrustpath, "sm2", 0);
    }
//===========================================abcjew2.8����==============================================================

    /**
     * ��ȡ����֤���base64��Ϣ�Լ�֤��DN
     */
    @DataProvider(name = "allcert-dn")
    public static Object[] getAllBase64CertAndDN() {
        return DataProviderUtil.getBase64CertAndAttr("DN",ParameterUtil.allcertpath, "all");
    }

    /**
     * ��ȡ����֤���base64��Ϣ�Լ�֤��SN
     */
    @DataProvider(name = "allcert-sn")
    public static Object[] getAllBase64CertAndSN() {
        return DataProviderUtil.getBase64CertAndAttr("SN",ParameterUtil.allcertpath, "all");
    }

    /**
     * ��ȡ����֤���base64��Ϣ�Լ�֤��BankCode
     */
    @DataProvider(name = "allcert-bankcode")
    public static Object[] getAllBase64CertAndBankCode() {
        return DataProviderUtil.getBase64CertAndBankCode(ParameterUtil.allcertpath, "all");
    }

    /**
     * ��ȡ����֤���bankcode
     */
    @DataProvider(name = "bankcode")
    public static Object[] getBankCode() {
        return ParseFile.getBankCode(ParameterUtil.localdetailpath, ParameterUtil.allcertpath, "all");
    }

    /**
     * ��ȡ���жԳƼ����㷨��֤���base64��Ϣ�Լ�֤��DN
     * @return [Alg,DN%Base64Cert]
     */
    @DataProvider(name = "symmalg-allcert-dn")
    public static Object[][] getAllSymmAlgWithBase64CertAndDN() {
        return DataProviderUtil.getAlgWithBase64CertAndAttr("DN",ParameterUtil.allcertpath, "all", 0);
    }

    /**
     * ��ȡ���жԳƼ����㷨��֤���base64��Ϣ�Լ�֤��SN
     * @return [Alg,SN%Base64Cert]
     */
    @DataProvider(name = "symmalg-allcert-sn")
    public static Object[][] getAllSymmAlgWithBase64CertAndSN() {
        return DataProviderUtil.getAlgWithBase64CertAndAttr("SN",ParameterUtil.allcertpath, "all", 0);
    }

    /**
     * ��ȡ���жԳƼ����㷨��֤��bankcode
     * @return [bankcode,alg]
     */
    @DataProvider(name = "all-symmalg-bankcode")
    public static Object[][] getAllSymmAlgWithBankCode() {
        return DataProviderUtil.composeCertAttrWithAlg("bankcode", false, true, ParameterUtil.allcertpath, "all", 0);
    }

    /**
     * ��ȡ����֤���DN,�Գ��㷨ΪSM4/AES
     * @return [dn,salg]
     */
    @DataProvider(name = "salg-16-alldn")
    public static Object[][] getSAlg16WithCertDN() {
        return DataProviderUtil.composeCertAttrWithAlg("DN", false, true, ParameterUtil.allcertpath, "all", 16);
    }

    /**
     * ��ȡ����֤���DN,�Գ��㷨Ϊ3DES/DES/RC2/RC4
     * @return [dn,salg]
     */
    @DataProvider(name = "salg-8-alldn")
    public static Object[][] getSAlg8WithCertDN() {
        return DataProviderUtil.composeCertAttrWithAlg("DN", false, true, ParameterUtil.allcertpath, "all", 8);
    }

    /**
     * ��ȡ����֤���SN,�Գ��㷨ΪSM4/AES
     * @return [sn,salg]
     */
    @DataProvider(name = "salg-16-allsn")
    public static Object[][] getSAlg16WithCertSN() {
        return DataProviderUtil.composeCertAttrWithAlg("SN", false, true, ParameterUtil.allcertpath, "all", 16);
    }

    /**
     * ��ȡ����֤���bankcode,�Գ��㷨ΪSM4/AES
     * @return [bankcode,salg]
     */
    @DataProvider(name = "salg-16-allbankcode")
    public static Object[][] getSAlg16WithCertBankCode() {
        return DataProviderUtil.composeCertAttrWithAlg("bankcode", false, true, ParameterUtil.allcertpath, "all", 16);
    }

    /**
     * ��ȡRSA֤��DN��RSAժҪ�㷨�����жԳ��㷨
     * @return [dn,dalg,salg]
     */
    @DataProvider(name = "rsa-dn-dalg-0")
    public static Object[][] rsaCertDNAndDAlgWithAllSAlg(){
        return DataProviderUtil.composeCertAttrWithAlg("dn", true, true, ParameterUtil.allcertpath, "rsa", 0);
    }

    /**
     * ��ȡ����RSA֤��DN��RSAժҪ�㷨�����жԳ��㷨
     * @return [dn,dalg,salg]
     */
    @DataProvider(name = "normal-rsa-dn-dalg-0")
    public static Object[][] normalRsaCertDN(){
        return DataProviderUtil.composeCertAttrWithAlg("dn", true, true, ParameterUtil.normalpath, "rsa", 0);
    }

    /**
     * ��ȡ����RSA֤��DN
     * @return [dn]
     */
    @DataProvider(name = "revoke-rsa-dn")
    public static Object[][] revokedRsaCertDN(){
        return DataProviderUtil.composeCertAttrWithAlg("dn", false, false, ParameterUtil.revokepath, "rsa", 0);
    }

    /**
     * ��ȡ����RSA֤��DN
     * @return [dn]
     */
    @DataProvider(name = "expire-rsa-dn")
    public static Object[][] expireRsaCertDN(){
        return DataProviderUtil.composeCertAttrWithAlg("dn", false, false, ParameterUtil.expirepath, "rsa", 0);
    }
    
    /**
     * ��ȡ����������RSA֤��DN
     * @return [dn]
     */
    @DataProvider(name = "nottrust-rsa-dn")
    public static Object[][] nottrustRsaCertDN(){
        return DataProviderUtil.composeCertAttrWithAlg("dn", false, false, ParameterUtil.nottrustpath, "rsa", 0);
    }

    /**
     * ��ȡ����SM2֤��DN��SM2ժҪ�㷨�����жԳ��㷨
     * @return [dn,dalg,salg]
     */
    @DataProvider(name = "normal-sm2-dn-dalg-0")
    public static Object[][] normalSm2CertDNAndDAlgWithAllSAlg(){
        return DataProviderUtil.composeCertAttrWithAlg("dn", true, true, ParameterUtil.normalpath, "sm2", 0);
    }

    /**
     * ��ȡ����SM2֤��DN
     * @return [dn]
     */
    @DataProvider(name = "revoke-sm2-dn")
    public static Object[][] revokedSm2CertDN(){
        return DataProviderUtil.composeCertAttrWithAlg("dn", false, false, ParameterUtil.revokepath, "sm2", 0);
    }

    /**
     * ��ȡ����SM2֤��DN
     * @return [dn]
     */
    @DataProvider(name = "expire-sm2-dn")
    public static Object[][] expireSm2CertDN(){
        return DataProviderUtil.composeCertAttrWithAlg("dn", false, false, ParameterUtil.expirepath, "sm2", 0);
    }
    
    /**
     * ��ȡ����RSA֤��SN��RSAժҪ�㷨�����жԳ��㷨
     * @return [sn,dalg,salg]
     */
    @DataProvider(name = "normal-rsa-sn-dalg-0")
    public static Object[][] normalRsaCertSNAndDAlgWithAllSAlg(){
        return DataProviderUtil.composeCertAttrWithAlg("sn", true, true, ParameterUtil.normalpath, "rsa", 0);
    }

    /**
     * ��ȡ����RSA֤��SN
     * @return [sn]
     */
    @DataProvider(name = "revoke-rsa-sn")
    public static Object[][] revokedRsaCertSN(){
        return DataProviderUtil.composeCertAttrWithAlg("sn", false, false, ParameterUtil.revokepath, "rsa", 0);
    }

    /**
     * ��ȡ����RSA֤��SN
     * @return [sn]
     */
    @DataProvider(name = "expire-rsa-sn")
    public static Object[][] expireRsaCertSN(){
        return DataProviderUtil.composeCertAttrWithAlg("sn", false, false, ParameterUtil.expirepath, "rsa", 0);
    }

    /**
     * ��ȡ����������RSA֤��SN
     * @return [sn]
     */
    @DataProvider(name = "nottrust-rsa-sn")
    public static Object[][] nottrustRsaCertSN(){
        return DataProviderUtil.composeCertAttrWithAlg("sn", false, false, ParameterUtil.nottrustpath, "rsa", 0);
    }

    /**
     * ��ȡ����SM2֤��SN��SM2ժҪ�㷨�����жԳ��㷨
     * @return [sn,dalg,salg]
     */
    @DataProvider(name = "normal-sm2-sn-dalg-0")
    public static Object[][] normalSm2CertSNAndDAlgWithAllSAlg(){
        return DataProviderUtil.composeCertAttrWithAlg("sn", true, true, ParameterUtil.normalpath, "sm2", 0);
    }

    /**
     * ��ȡ����SM2֤��SN
     * @return [sn]
     */
    @DataProvider(name = "revoke-sm2-sn")
    public static Object[][] revokedSm2CertSN(){
        return DataProviderUtil.composeCertAttrWithAlg("sn", false, false, ParameterUtil.revokepath, "sm2", 0);
    }

    /**
     * ��ȡ����SM2֤��SN
     * @return [sn]
     */
    @DataProvider(name = "expire-sm2-sn")
    public static Object[][] expireSm2CertSN(){
        return DataProviderUtil.composeCertAttrWithAlg("sn", false, false, ParameterUtil.expirepath, "sm2", 0);
    }
    
    /**
     * ��ȡ����RSA֤��Bankcode��RSAժҪ�㷨�����жԳ��㷨
     * @return [bankcode,dalg,salg]
     */
    @DataProvider(name = "normal-rsa-bankcode-dalg-0")
    public static Object[][] normalRsaCertBankcode(){
        return DataProviderUtil.composeCertAttrWithAlg("bankcode", true, true, ParameterUtil.normalpath, "rsa", 0);
    }

    /**
     * ��ȡ����RSA֤��Bankcode
     * @return [bankcode]
     */
    @DataProvider(name = "revoke-rsa-bankcode")
    public static Object[][] revokedRsaCertBankcode(){
        return DataProviderUtil.composeCertAttrWithAlg("bankcode", false, false, ParameterUtil.revokepath, "rsa", 0);
    }

    /**
     * ��ȡ����RSA֤��Bankcode
     * @return [bankcode]
     */
    @DataProvider(name = "expire-rsa-bankcode")
    public static Object[][] expireRsaCertBankcode(){
        return DataProviderUtil.composeCertAttrWithAlg("bankcode", false, false, ParameterUtil.expirepath, "rsa", 0);
    }

    /**
     * ��ȡ����������RSA֤��Bankcode
     * @return [bankcode]
     */
    @DataProvider(name = "nottrust-rsa-bankcode")
    public static Object[][] nottrustRsaCertBankcode(){
        return DataProviderUtil.composeCertAttrWithAlg("bankcode", false, false, ParameterUtil.nottrustpath, "rsa", 0);
    }

    /**
     * ��ȡ����SM2֤��Bankcode��SM2ժҪ�㷨�����жԳ��㷨
     * @return [bankcode,dalg,salg]
     */
    @DataProvider(name = "normal-sm2-bankcode-dalg-0")
    public static Object[][] normalSm2CertBankcodeAndDAlgWithAllSAlg(){
        return DataProviderUtil.composeCertAttrWithAlg("bankcode", true, true, ParameterUtil.normalpath, "sm2", 0);
    }

    /**
     * ��ȡ����SM2֤��Bankcode
     * @return [bankcode]
     */
    @DataProvider(name = "revoke-sm2-bankcode")
    public static Object[][] revokedSm2CertBankcode(){
        return DataProviderUtil.composeCertAttrWithAlg("bankcode", false, false, ParameterUtil.revokepath, "sm2", 0);
    }

    /**
     * ��ȡ����SM2֤��Bankcode
     * @return [bankcode]
     */
    @DataProvider(name = "expire-sm2-bankcode")
    public static Object[][] expireSm2CertBankcode(){
        return DataProviderUtil.composeCertAttrWithAlg("bankcode", false, false, ParameterUtil.expirepath, "sm2", 0);
    }

    /**
     * ��ȡSM2֤��DN��SM2ժҪ�㷨�����жԳ��㷨
     * @return [dn,dalg,salg]
     */
    @DataProvider(name = "sm2-dn-dalg-0")
    public static Object[][] sm2CertDNAndDAlgWithAllSAlg(){
        return DataProviderUtil.composeCertAttrWithAlg("dn", true, true, ParameterUtil.allcertpath, "sm2", 0);
    }

    /**
     * ��ȡRSA֤��SN��RSAժҪ�㷨�����жԳ��㷨
     * @return [sn,dalg,salg]
     */
    @DataProvider(name = "rsa-sn-dalg-0")
    public static Object[][] rsaCertSNAndDAlgWithAllSAlg(){
        return DataProviderUtil.composeCertAttrWithAlg("sn", true, true, ParameterUtil.allcertpath, "rsa", 0);
    }

    /**
     * ��ȡSM2֤��SN��SM2ժҪ�㷨�����жԳ��㷨
     * @return [sn,dalg,salg]
     */
    @DataProvider(name = "sm2-sn-dalg-0")
    public static Object[][] sm2CertSNAndDAlgWithAllSAlg(){
        return DataProviderUtil.composeCertAttrWithAlg("sn", true, true, ParameterUtil.allcertpath, "sm2", 0);
    }

    /**
     * ��ȡRSA֤��Bankcode��RSAժҪ�㷨�����жԳ��㷨
     * @return [bankcode,dalg,salg]
     */
    @DataProvider(name = "rsa-bankcode-dalg-0")
    public static Object[][] rsaBankCodeAndDAlgWithAllSAlg(){
        return DataProviderUtil.composeCertAttrWithAlg("bankcode", true, true, ParameterUtil.allcertpath, "rsa", 0);
    }

    /**
     * ��ȡSM2֤��Bankcode��SM2ժҪ�㷨�����жԳ��㷨
     * @return [bankcode,dalg,salg]
     */
    @DataProvider(name = "sm2-bankcode-dalg-0")
    public static Object[][] sm2BankCodeAndDAlgWithAllSAlg(){
        return DataProviderUtil.composeCertAttrWithAlg("bankcode", true, true, ParameterUtil.allcertpath, "sm2", 0);
    }

    /**
     * ��������Դ,����SM2��RSA����֤��DN��ժҪ�㷨
     *
     * @return ��alg��dn��
     */
    @DataProvider(name = "all-alg-dn")
    public static Object[][] AllAlgDN() {
        return DataProviderUtil.resolveAlgDN(ParameterUtil.allcertpath);
    }

    /**
     * ��������Դ,����SM2��RSA����֤��SN��ժҪ�㷨
     *
     * @return ��alg��sn��
     */
    @DataProvider(name = "all-alg-sn")
    public static Object[][] AllAlgSN(){
        return DataProviderUtil.resolveAlgSN(ParameterUtil.allcertpath);
    }

    /**
     * ��������Դ,����SM2��RSA����֤��SN��ժҪ�㷨
     *
     * @return ��alg��sn��
     */
    @DataProvider(name = "normal-alg-sn")
    public static Object[][] NormalAlgSN(){
        return DataProviderUtil.resolveAlgSN(ParameterUtil.normalpath);
    }

    /**
     * ��ȡ�������뼰ժҪ,����֤��
     *
     * @return ��alg��bankcode��
     */
    @DataProvider(name = "all-alg-bankcode")
    public static Object[][] allbankCodeAlg() {
        return DataProviderUtil.bankCodeAlg(ParameterUtil.allcertpath);
    }

    /**
     * ��ȡSM2��RSA����֤��DN��ժҪ�㷨�͹�Կ֤��
     *
     * @return ��alg��dn ��cert��
     */
    @DataProvider(name = "normal-alg-dn-cert")
    public static Object[][] NormalAlgDNCert(){
        return DataProviderUtil.resolveAlgDNCert(ParameterUtil.normalpath);
    }


    /**
     * ��ȡSM2��RSA����֤��DN
     *
     * @return ��dn��
     */
    @DataProvider(name = "normal-dn")
    public static Object[] NormalDN(){
        return ParseCert.parseCertByAttributes("DN", ParameterUtil.normalpath, "all");
    }

    /**
     * ��ȡ����RSA֤��DN��ժҪ�㷨
     * @return [dn,alg]
     */
    @DataProvider(name = "normal-rsa-dn-dalg")
    public static Object[][] normalRSACertDNAndAlg(){
        return DataProviderUtil.composeCertAttrWithAlg("dn", true, false, ParameterUtil.normalpath, "rsa", 0);
    }

    /**
     * ��ȡ����RSA֤��DN��ժҪ�㷨
     * @return [dn,alg]
     */
    @DataProvider(name = "revoke-rsa-dn-dalg")
    public static Object[][] revokeRSACertDNAndAlg(){
        return DataProviderUtil.composeCertAttrWithAlg("dn", true, false, ParameterUtil.revokepath, "rsa", 0);
    }

    /**
     * ��ȡ����RSA֤��DN��ժҪ�㷨
     * @return [dn,alg]
     */
    @DataProvider(name = "expire-rsa-dn-dalg")
    public static Object[][] expireRSACertDNAndAlg(){
        return DataProviderUtil.composeCertAttrWithAlg("dn", true, false, ParameterUtil.expirepath, "rsa", 0);
    }

    /**
     * ��ȡ��������RSA֤��DN��ժҪ�㷨
     * @return [dn,alg]
     */
    @DataProvider(name = "nottrust-rsa-dn-dalg")
    public static Object[][] nottrustRSACertDNAndAlg(){
        return DataProviderUtil.composeCertAttrWithAlg("dn", true, false, ParameterUtil.nottrustpath, "rsa", 0);
    }

    /**
     * ��ȡ����RSA֤��SN��ժҪ�㷨
     * @return [sn,alg]
     */
    @DataProvider(name = "normal-rsa-sn-dalg")
    public static Object[][] normalRSACertSNAndAlg(){
        return DataProviderUtil.composeCertAttrWithAlg("sn", true, false, ParameterUtil.normalpath, "rsa", 0);
    }

    /**
     * ��ȡ����RSA֤��SN��ժҪ�㷨
     * @return [sn,alg]
     */
    @DataProvider(name = "revoke-rsa-sn-dalg")
    public static Object[][] revokeRSACertSNAndAlg(){
        return DataProviderUtil.composeCertAttrWithAlg("sn", true, false, ParameterUtil.revokepath, "rsa", 0);
    }

    /**
     * ��ȡ����RSA֤��SN��ժҪ�㷨
     * @return [sn,alg]
     */
    @DataProvider(name = "expire-rsa-sn-dalg")
    public static Object[][] expireRSACertSNAndAlg(){
        return DataProviderUtil.composeCertAttrWithAlg("sn", true, false, ParameterUtil.expirepath, "rsa", 0);
    }

    /**
     * ��ȡ��������RSA֤��SN��ժҪ�㷨
     * @return [sn,alg]
     */
    @DataProvider(name = "nottrust-rsa-sn-dalg")
    public static Object[][] nottrustRSACertSNAndAlg(){
        return DataProviderUtil.composeCertAttrWithAlg("sn", true, false, ParameterUtil.nottrustpath, "rsa", 0);
    }

    /**
     * ��ȡ����RSA֤��Bankcode��ժҪ�㷨
     * @return [bankcode,alg]
     */
    @DataProvider(name = "normal-rsa-bankcode-dalg")
    public static Object[][] normalRSACertBankcodeAndAlg(){
        return DataProviderUtil.composeCertAttrWithAlg("bankcode", true, false, ParameterUtil.normalpath, "rsa", 0);
    }

    /**
     * ��ȡ����RSA֤��Bankcode��ժҪ�㷨
     * @return [bankcode,alg]
     */
    @DataProvider(name = "revoke-rsa-bankcode-dalg")
    public static Object[][] revokeRSACertBankcodeAndAlg(){
        return DataProviderUtil.composeCertAttrWithAlg("bankcode", true, false, ParameterUtil.revokepath, "rsa", 0);
    }

    /**
     * ��ȡ����RSA֤��Bankcode��ժҪ�㷨
     * @return [bankcode,alg]
     */
    @DataProvider(name = "expire-rsa-bankcode-dalg")
    public static Object[][] expireRSACertBankcodeAndAlg(){
        return DataProviderUtil.composeCertAttrWithAlg("bankcode", true, false, ParameterUtil.expirepath, "rsa", 0);
    }

    /**
     * ��ȡ��������RSA֤��Bankcode��ժҪ�㷨
     * @return [bankcode,alg]
     */
    @DataProvider(name = "nottrust-rsa-bankcode-dalg")
    public static Object[][] nottrustRSACertBankcodeAndAlg(){
        return DataProviderUtil.composeCertAttrWithAlg("bankcode", true, false, ParameterUtil.nottrustpath, "rsa", 0);
    }

    /**
     * ��ȡ����SM2֤��DN��ժҪ�㷨
     * @return [dn,alg]
     */
    @DataProvider(name = "normal-sm2-dn-dalg")
    public static Object[][] normalSM2CertDNAndAlg(){
        return DataProviderUtil.composeCertAttrWithAlg("dn", true, false, ParameterUtil.normalpath, "sm2", 0);
    }

    /**
     * ��ȡ����SM2֤��DN��ժҪ�㷨
     * @return [dn,alg]
     */
    @DataProvider(name = "revoke-sm2-dn-dalg")
    public static Object[][] revokeSM2CertDNAndAlg(){
        return DataProviderUtil.composeCertAttrWithAlg("dn", true, false, ParameterUtil.revokepath, "sm2", 0);
    }

    /**
     * ��ȡ����SM2֤��DN��ժҪ�㷨
     * @return [dn,alg]
     */
    @DataProvider(name = "expire-sm2-dn-dalg")
    public static Object[][] expireSM2CertDNAndAlg(){
        return DataProviderUtil.composeCertAttrWithAlg("dn", true, false, ParameterUtil.expirepath, "sm2", 0);
    }

    /**
     * ��ȡ��������SM2֤��DN��ժҪ�㷨
     * @return [dn,alg]
     */
    @DataProvider(name = "nottrust-sm2-dn-dalg")
    public static Object[][] nottrustSM2CertDNAndAlg(){
        return DataProviderUtil.composeCertAttrWithAlg("dn", true, false, ParameterUtil.nottrustpath, "sm2", 0);
    }

    /**
     * ��ȡ����SM2֤��SN��ժҪ�㷨
     * @return [sn,alg]
     */
    @DataProvider(name = "normal-sm2-sn-dalg")
    public static Object[][] normalSM2CertSNAndAlg(){
        return DataProviderUtil.composeCertAttrWithAlg("sn", true, false, ParameterUtil.normalpath, "sm2", 0);
    }

    /**
     * ��ȡ����SM2֤��SN��ժҪ�㷨
     * @return [sn,alg]
     */
    @DataProvider(name = "revoke-sm2-sn-dalg")
    public static Object[][] revokeSM2CertSNAndAlg(){
        return DataProviderUtil.composeCertAttrWithAlg("sn", true, false, ParameterUtil.revokepath, "sm2", 0);
    }

    /**
     * ��ȡ����SM2֤��SN��ժҪ�㷨
     * @return [sn,alg]
     */
    @DataProvider(name = "expire-sm2-sn-dalg")
    public static Object[][] expireSM2CertSNAndAlg(){
        return DataProviderUtil.composeCertAttrWithAlg("sn", true, false, ParameterUtil.expirepath, "sm2", 0);
    }

    /**
     * ��ȡ��������SM2֤��SN��ժҪ�㷨
     * @return [sn,alg]
     */
    @DataProvider(name = "nottrust-sm2-sn-dalg")
    public static Object[][] nottrustSM2CertSNAndAlg(){
        return DataProviderUtil.composeCertAttrWithAlg("sn", true, false, ParameterUtil.nottrustpath, "sm2", 0);
    }

    /**
     * ��ȡ����SM2֤��Bankcode��ժҪ�㷨
     * @return [bankcode,alg]
     */
    @DataProvider(name = "normal-sm2-bankcode-dalg")
    public static Object[][] normalSM2CertBankcodeAndAlg(){
        return DataProviderUtil.composeCertAttrWithAlg("bankcode", true, false, ParameterUtil.normalpath, "sm2", 0);
    }

    /**
     * ��ȡ����SM2֤��Bankcode��ժҪ�㷨
     * @return [bankcode,alg]
     */
    @DataProvider(name = "revoke-sm2-bankcode-dalg")
    public static Object[][] revokeSM2CertBankcodeAndAlg(){
        return DataProviderUtil.composeCertAttrWithAlg("bankcode", true, false, ParameterUtil.revokepath, "sm2", 0);
    }

    /**
     * ��ȡ����SM2֤��Bankcode��ժҪ�㷨
     * @return [bankcode,alg]
     */
    @DataProvider(name = "expire-sm2-bankcode-dalg")
    public static Object[][] expireSM2CertBankcodeAndAlg(){
        return DataProviderUtil.composeCertAttrWithAlg("bankcode", true, false, ParameterUtil.expirepath, "sm2", 0);
    }

    /**
     * ��ȡ��������SM2֤��Bankcode��ժҪ�㷨
     * @return [bankcode,alg]
     */
    @DataProvider(name = "nottrust-sm2-bankcode-dalg")
    public static Object[][] nottrustSM2CertBankcodeAndAlg(){
        return DataProviderUtil.composeCertAttrWithAlg("bankcode", true, false, ParameterUtil.nottrustpath, "sm2", 0);
    }

    /**
     * ��ȡ����RSA֤��DN��Base64��Ϣ�Լ�ժҪ�㷨
     * @return [dn%base64Cert,salg]
     */
    @DataProvider(name = "normal-rsa-dn-base64-salg")
    public static Object[][] normalRSABase64CertAndDNWithSAlg(){
        return DataProviderUtil.getBase64CertAndAttrWithSAlg("DN",ParameterUtil.normalpath,"rsa");
    }
    /**
     * ��ȡ����RSA֤��DN��Base64��Ϣ�Լ�ժҪ�㷨
     * @return [dn%base64Cert,salg]
     */
    @DataProvider(name = "expire-rsa-dn-base64-salg")
    public static Object[][] expireRSABase64CertAndDNWithSAlg(){
        return DataProviderUtil.getBase64CertAndAttrWithSAlg("DN",ParameterUtil.expirepath,"rsa");
    }
    /**
     * ��ȡ����RSA֤��DN��Base64��Ϣ�Լ�ժҪ�㷨
     * @return [dn%base64Cert,salg]
     */
    @DataProvider(name = "revoke-rsa-dn-base64-salg")
    public static Object[][] revokeRSABase64CertAndDNWithSAlg(){
        return DataProviderUtil.getBase64CertAndAttrWithSAlg("DN",ParameterUtil.revokepath,"rsa");
    }
    /**
     * ��ȡ��������RSA֤��DN��Base64��Ϣ�Լ�ժҪ�㷨
     * @return [dn%base64Cert,salg]
     */
    @DataProvider(name = "nottrust-rsa-dn-base64-salg")
    public static Object[][] nottrustRSABase64CertAndDNWithSAlg(){
        return DataProviderUtil.getBase64CertAndAttrWithSAlg("DN",ParameterUtil.nottrustpath,"rsa");
    }

    /**
     * ��ȡ����RSA֤��SN��Base64��Ϣ�Լ�ժҪ�㷨
     * @return [sn%base64Cert,salg]
     */
    @DataProvider(name = "normal-rsa-sn-base64-salg")
    public static Object[][] normalRSABase64CertAndSNWithSAlg(){
        return DataProviderUtil.getBase64CertAndAttrWithSAlg("SN",ParameterUtil.normalpath,"rsa");
    }
    /**
     * ��ȡ����RSA֤��SN��Base64��Ϣ�Լ�ժҪ�㷨
     * @return [sn%base64Cert,salg]
     */
    @DataProvider(name = "expire-rsa-sn-base64-salg")
    public static Object[][] expireRSABase64CertAndSNWithSAlg(){
        return DataProviderUtil.getBase64CertAndAttrWithSAlg("SN",ParameterUtil.expirepath,"rsa");
    }
    /**
     * ��ȡ����RSA֤��SN��Base64��Ϣ�Լ�ժҪ�㷨
     * @return [sn%base64Cert,salg]
     */
    @DataProvider(name = "revoke-rsa-sn-base64-salg")
    public static Object[][] revokeRSABase64CertAndSNWithSAlg(){
        return DataProviderUtil.getBase64CertAndAttrWithSAlg("SN",ParameterUtil.revokepath,"rsa");
    }
    /**
     * ��ȡ��������RSA֤��SN��Base64��Ϣ�Լ�ժҪ�㷨
     * @return [sn%base64Cert,salg]
     */
    @DataProvider(name = "nottrust-rsa-sn-base64-salg")
    public static Object[][] nottrustRSABase64CertAndSNWithSAlg(){
        return DataProviderUtil.getBase64CertAndAttrWithSAlg("SN",ParameterUtil.nottrustpath,"rsa");
    }

    /**
     * ��ȡ����SM2֤��DN��Base64��Ϣ�Լ�ժҪ�㷨
     * @return [dn%base64Cert,salg]
     */
    @DataProvider(name = "normal-sm2-dn-base64-salg")
    public static Object[][] normalSM2Base64CertAndDNWithSAlg(){
        return DataProviderUtil.getBase64CertAndAttrWithSAlg("DN",ParameterUtil.normalpath,"sm2");
    }
    /**
     * ��ȡ����SM2֤��DN��Base64��Ϣ�Լ�ժҪ�㷨
     * @return [dn%base64Cert,salg]
     */
    @DataProvider(name = "expire-sm2-dn-base64-salg")
    public static Object[][] expireSM2Base64CertAndDNWithSAlg(){
        return DataProviderUtil.getBase64CertAndAttrWithSAlg("DN",ParameterUtil.expirepath,"sm2");
    }
    /**
     * ��ȡ����SM2֤��DN��Base64��Ϣ�Լ�ժҪ�㷨
     * @return [dn%base64Cert,salg]
     */
    @DataProvider(name = "revoke-sm2-dn-base64-salg")
    public static Object[][] revokeSM2Base64CertAndDNWithSAlg(){
        return DataProviderUtil.getBase64CertAndAttrWithSAlg("DN",ParameterUtil.revokepath,"sm2");
    }
    /**
     * ��ȡ��������SM2֤��DN��Base64��Ϣ�Լ�ժҪ�㷨
     * @return [dn%base64Cert,salg]
     */
    @DataProvider(name = "nottrust-sm2-dn-base64-salg")
    public static Object[][] nottrustSM2Base64CertAndDNWithSAlg(){
        return DataProviderUtil.getBase64CertAndAttrWithSAlg("DN",ParameterUtil.nottrustpath,"sm2");
    }

    /**
     * ��ȡ����SM2֤��SN��Base64��Ϣ�Լ�ժҪ�㷨
     * @return [sn%base64Cert,salg]
     */
    @DataProvider(name = "normal-sm2-sn-base64-salg")
    public static Object[][] normalSM2Base64CertAndSNWithSAlg(){
        return DataProviderUtil.getBase64CertAndAttrWithSAlg("SN",ParameterUtil.normalpath,"sm2");
    }
    /**
     * ��ȡ����SM2֤��SN��Base64��Ϣ�Լ�ժҪ�㷨
     * @return [sn%base64Cert,salg]
     */
    @DataProvider(name = "expire-sm2-sn-base64-salg")
    public static Object[][] expireSM2Base64CertAndSNWithSAlg(){
        return DataProviderUtil.getBase64CertAndAttrWithSAlg("SN",ParameterUtil.expirepath,"sm2");
    }
    /**
     * ��ȡ����SM2֤��SN��Base64��Ϣ�Լ�ժҪ�㷨
     * @return [sn%base64Cert,salg]
     */
    @DataProvider(name = "revoke-sm2-sn-base64-salg")
    public static Object[][] revokeSM2Base64CertAndSNWithSAlg(){
        return DataProviderUtil.getBase64CertAndAttrWithSAlg("SN",ParameterUtil.revokepath,"sm2");
    }
    /**
     * ��ȡ��������SM2֤��SN��Base64��Ϣ�Լ�ժҪ�㷨
     * @return [sn%base64Cert,salg]
     */
    @DataProvider(name = "nottrust-sm2-sn-base64-salg")
    public static Object[][] nottrustSM2Base64CertAndSNWithSAlg(){
        return DataProviderUtil.getBase64CertAndAttrWithSAlg("SN",ParameterUtil.nottrustpath,"sm2");
    }
}
