package qa.infosec.testng.netsign.upki;

import cn.com.infosec.netsign.agent.UpkiAgent;
import cn.com.infosec.netsign.agent.UpkiResult;
import org.testng.Assert;
import org.testng.Reporter;
import org.testng.annotations.Test;
import qa.infosec.testng.netsign.dataprovider.NetSignDataProvider;
import qa.infosec.testng.netsign.dataprovider.util.ParameterUtil;
import qa.infosec.testng.netsign.dataprovider.util.ParseFile;
import qa.infosec.testng.netsign.dataprovider.util.SFTPFile;
import qa.infosec.testng.netsign.dataprovider.util.Utils;
import qa.infosec.testng.netsign.init.NetSignServerInit;

import java.util.Map;

/**
 * @author zhaoyongzhi
 * @ClassName: TestEncryptAndSignEnvelope
 * @date 2020-03-02 18:07
 * @Description: ������ǩ���������ŷ�
 * <p>�������ǵ㣺</p>
 * <p>1��������ǩ���������ŷ⣬ʹ��RSA֤��DN</p>
 * <p>2��������ǩ���������ŷ⣬ʹ��SM2֤��DN</p>
 * <p>3��������ǩ���������ŷ⣬ʹ��RSA֤��SN</p>
 * <p>4��������ǩ���������ŷ⣬ʹ��SM2֤��SN</p>
 * <p>5��������ǩ���������ŷ⣬ʹ��RSA֤��BankCode</p>
 * <p>6��������ǩ���������ŷ⣬ʹ��SM2֤��BankCode</p>
 * <p>7��������ǩ���������ŷ⣬ԭ��Ϊnull</p>
 * <p>8��������ǩ���������ŷ⣬DN/SN/BankcodeΪ�ջ�null</p>
 * <p>9��������ǩ���������ŷ⣬ժҪ/�Գ��㷨Ϊ�ջ�null</p>
 * <p>10��������ǩ���������ŷ⣬DN������</p>
 * <p>11��������ǩ���������ŷ⣬ժҪ�㷨����</p>
 * <p>12��������ǩ���������ŷ⣬�Գ��㷨����</p>
 * <p>13��������ǩ���������ŷ⣬ժҪ/�Գ��㷨Сд����</p>
 */
@Test(groups = "abcjew.encryptandsignenvelope")
public class TestEncryptAndSignEnvelope {
    static String ip, port, password;
    static String host, sftp_port, sftp_password, sftp_user;

    NetSignServerInit init = new NetSignServerInit();
    UpkiAgent agent;
    SFTPFile tmp = new SFTPFile();

    {
        Map<String, String> map = ParseFile.parseProperties(null);
        ip = map.get("ServerIP");
        port = map.get("ServerPortPBC2G");
        password = map.get("APIPassword");

        host = map.get("sftp_ip");
        sftp_port = map.get("sftp_port");
        sftp_user = map.get("sftp_user");
        sftp_password = map.get("sftp_password");

        agent = init.upkiStart(ip, port, password, true, 20);
        tmp.downFile(sftp_user, host, sftp_port, sftp_password, ParameterUtil.sftpdetailpath,
                ParameterUtil.localdetailpath);
    }

    /**
     * ������ǩ���������ŷ⣬ʹ��RSA֤��DN
     *
     * @param DN   RSA֤��DN
     * @param dAlg SHA1/SHA224/SHA256/SHA384/SHA512
     * @param sAlg SM4/AES/RC2/RC4/DES/3DES
     */
    @Test(groups = "abcjew.encryptandsignenvelope.normal", dataProvider = "rsa-dn-dalg-0", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptAndSignEnvelope_01(String DN, String dAlg, String sAlg) {
        System.out.println("������ǩ���������ŷ⣨encryptAndSignEnvelope����ʹ��RSA֤��DN");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, DN, DN, dAlg, sAlg);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("������ǩ���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ������ǩ���������ŷ⣬ʹ��SM2֤��DN
     *
     * @param DN   SM2֤��DN
     * @param dAlg SHA1/SHA256/SM3
     * @param sAlg SM4/AES/RC2/RC4/DES/3DES
     */
    @Test(groups = "abcjew.encryptandsignenvelope.normal", dataProvider = "sm2-dn-dalg-0", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptAndSignEnvelope_02(String DN, String dAlg, String sAlg) {
        System.out.println("������ǩ���������ŷ⣨encryptAndSignEnvelope����ʹ��SM2֤��DN");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, DN, DN, dAlg, sAlg);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("������ǩ���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ������ǩ���������ŷ⣬ʹ��RSA֤��SN
     *
     * @param SN   RSA֤��SN
     * @param dAlg SHA1/SHA224/SHA256/SHA384/SHA512
     * @param sAlg SM4/AES/RC2/RC4/DES/3DES
     */
    @Test(groups = "abcjew.encryptandsignenvelope.normal", dataProvider = "rsa-sn-dalg-0", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptAndSignEnvelope_03(String SN, String dAlg, String sAlg) {
        System.out.println("������ǩ���������ŷ⣨encryptAndSignEnvelope����ʹ��RSA֤��SN");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, SN, SN, dAlg, sAlg);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("������ǩ���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ������ǩ���������ŷ⣬ʹ��SM2֤��SN
     *
     * @param SN   SM2֤��SN
     * @param dAlg SHA1/SHA256/SM3
     * @param sAlg SM4/AES/RC2/RC4/DES/3DES
     */
    @Test(groups = "abcjew.encryptandsignenvelope.normal", dataProvider = "sm2-sn-dalg-0", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptAndSignEnvelope_04(String SN, String dAlg, String sAlg) {
        System.out.println("������ǩ���������ŷ⣨encryptAndSignEnvelope����ʹ��SM2֤��SN");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, SN, SN, dAlg, sAlg);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("������ǩ���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ������ǩ���������ŷ⣬ʹ��RSA֤��Bankcode
     *
     * @param dAlg SHA1/SHA224/SHA256/SHA384/SHA512
     * @param sAlg SM4/AES/RC2/RC4/DES/3DES
     */
    @Test(groups = "abcjew.encryptandsignenvelope.normal", dataProvider = "rsa-bankcode-dalg-0", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptAndSignEnvelope_05(String bankcode, String dAlg, String sAlg) {
        System.out.println("������ǩ���������ŷ⣨encryptAndSignEnvelope����ʹ��RSA֤��BankCode");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, bankcode, bankcode, dAlg, sAlg);
            if (upkiResult.getReturnCode() != 0) {
                if (upkiResult.getReturnCode() != -100203 && upkiResult.getReturnCode() != -100204) {
                    Assert.fail("������ǩ���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("������ǩ���������ŷ⣨encryptAndSignEnvelope��������֤���޷�ͨ��Bankcodeʶ�𣬵���ִ�з���ʱ���񱨴��޷��ҵ�֤������");
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ������ǩ���������ŷ⣬ʹ��SM2֤��Bankcode
     *
     * @param dAlg SHA1/SHA256/SM3
     * @param sAlg SM4/AES/RC2/RC4/DES/3DES
     */
    @Test(groups = "abcjew.encryptandsignenvelope.normal", dataProvider = "sm2-bankcode-dalg-0", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptAndSignEnvelope_06(String bankcode, String dAlg, String sAlg) {
        System.out.println("������ǩ���������ŷ⣨encryptAndSignEnvelope����ʹ��SM2֤��BankCode");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, bankcode, bankcode, dAlg, sAlg);
            if (upkiResult.getReturnCode() != 0) {
                if (upkiResult.getReturnCode() != -100203 && upkiResult.getReturnCode() != -100204) {
                    Assert.fail("������ǩ���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("������ǩ���������ŷ⣨encryptAndSignEnvelope��������֤���޷�ͨ��Bankcodeʶ�𣬵���ִ�з���ʱ���񱨴��޷��ҵ�֤������");
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ������ǩ���������ŷ⣬ԭ��Ϊnull
     *
     * @param DN   SM2֤��DN
     * @param dAlg SHA1/SHA224/SHA256/SHA384/SHA512
     * @param sAlg SM4/AES/RC2/RC4/DES/3DES
     */
    @Test(groups = "abcjew.encryptandsignenvelope.normal", dataProvider = "sm2-dn-dalg-0", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptAndSignEnvelope_07(String DN, String dAlg, String sAlg) {
        System.out.println("������ǩ���������ŷ⣨encryptAndSignEnvelope����ԭ��Ϊnull");

        byte[] pOrgData = null;
        UpkiResult upkiResult;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, DN, DN, dAlg, sAlg);
            if (upkiResult.getReturnCode() != -100208) {
                Assert.fail("������ǩ���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ������ǩ���������ŷ⣬DN/SN/BankcodeΪ�ջ�null
     *
     */
    @Test(groups = "abcjew.encryptandsignenvelope.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptAndSignEnvelope_08(String DN) {
        System.out.println("������ǩ���������ŷ⣨encryptAndSignEnvelope����DN/SN/BankcodeΪ�ջ�null");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String dAlg = "SHA1";
        String sAlg = "AES";
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, DN, DN, dAlg, sAlg);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("������ǩ���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            Reporter.log("������ǩ���������ŷ⣨encryptAndSignEnvelope��:DN/SN/BankcodeΪ�ջ�null������ҵ��ɹ�");
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ������ǩ���������ŷ⣬ժҪ/�Գ��㷨Ϊ�ջ�null
     *
     */
    @Test(groups = "abcjew.encryptandsignenvelope.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptAndSignEnvelope_09(String alg) {
        System.out.println("������ǩ���������ŷ⣨encryptAndSignEnvelope����ժҪ/�Գ��㷨Ϊ�ջ�null");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String DN = "CN=c020crlfbdIssueModeHTTP";
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, DN, DN, alg, alg);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("������ǩ���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            Reporter.log("������ǩ���������ŷ⣨encryptAndSignEnvelope��:ժҪ/�Գ��㷨Ϊ�ջ�null������ҵ��ɹ�");
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ������ǩ���������ŷ⣬DN������
     *
     */
    @Test(groups = "abcjew.encryptandsignenvelope.normal")
    public void testEncryptAndSignEnvelope_10() {
        System.out.println("������ǩ���������ŷ⣨encryptAndSignEnvelope����DN������");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String DN = "CN=c020crlfbdIssueModeHP";
        String dalg = "SHA1";
        String salg = "AES";
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, DN, DN, dalg, salg);
            if (upkiResult.getReturnCode() != -100204) {
                Assert.fail("������ǩ���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ������ǩ���������ŷ⣬ժҪ�㷨����
     *
     */
    @Test(groups = "abcjew.encryptandsignenvelope.normal")
    public void testEncryptAndSignEnvelope_11() {
        System.out.println("������ǩ���������ŷ⣨encryptAndSignEnvelope����ժҪ�㷨����");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String DN = "CN=c020crlfbdIssueModeHP";
        String dalg = "SHA";
        String salg = "AES";
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, DN, DN, dalg, salg);
            if (upkiResult.getReturnCode() != -100204) {
                Assert.fail("������ǩ���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ������ǩ���������ŷ⣬�Գ��㷨����
     *
     */
    @Test(groups = "abcjew.encryptandsignenvelope.normal")
    public void testEncryptAndSignEnvelope_12() {
        System.out.println("������ǩ���������ŷ⣨encryptAndSignEnvelope�����Գ��㷨����");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String DN = "CN=c020crlfbdIssueModeHP";
        String dalg = "SHA1";
        String salg = "AES1";
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, DN, DN, dalg, salg);
            if (upkiResult.getReturnCode() != -100204) {
                Assert.fail("������ǩ���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ������ǩ���������ŷ⣬ժҪ�㷨Сд����
     *
     * @param DN   RSA֤��DN
     * @param dAlg SHA1/SHA224/SHA256/SHA384/SHA512
     * @param sAlg SM4/AES/RC2/RC4/DES/3DES
     */
    @Test(groups = "abcjew.encryptandsignenvelope.normal", dataProvider = "rsa-dn-dalg-0", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptAndSignEnvelope_13(String DN, String dAlg, String sAlg) {
        System.out.println("������ǩ���������ŷ⣨encryptAndSignEnvelope����ժҪ�㷨Сд����");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, DN, DN, dAlg.toLowerCase(), sAlg);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("������ǩ���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ������ǩ���������ŷ⣬�Գ��㷨Сд����
     *
     * @param DN   RSA֤��DN
     * @param dAlg SHA1/SHA224/SHA256/SHA384/SHA512
     * @param sAlg SM4/AES/RC2/RC4/DES/3DES
     */
    @Test(groups = "abcjew.encryptandsignenvelope.normal", dataProvider = "rsa-dn-dalg-0", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptAndSignEnvelope_14(String DN, String dAlg, String sAlg) {
        System.out.println("������ǩ���������ŷ⣨encryptAndSignEnvelope�����Գ��㷨Сд����");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, DN, DN, dAlg, sAlg.toLowerCase());
            if (upkiResult.getReturnCode() != -100112) {
                Assert.fail("������ǩ���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            Reporter.log("������ǩ���������ŷ⣨encryptAndSignEnvelope�����Գ��㷨��֧��Сд����");
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }
}
