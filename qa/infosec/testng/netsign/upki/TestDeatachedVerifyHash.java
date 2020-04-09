package qa.infosec.testng.netsign.upki;

import cn.com.infosec.netsign.agent.UpkiAgent;
import cn.com.infosec.netsign.agent.UpkiResult;
import cn.com.infosec.util.Base64;
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
 * @ClassName: TestDeatachedVerifyHash
 * @date 2020-03-02 18:15
 * @Description: Detached��ժҪ
 * <p>�������ǵ㣺</p>
 * <p>1��Detached��ժҪ��detachedVerifyHash��:ʹ������RSA֤��DN��ǩ</p>
 * <p>2��Detached��ժҪ��detachedVerifyHash��:ʹ������RSA֤��DN��ǩ</p>
 * <p>3��Detached��ժҪ��detachedVerifyHash��:ʹ�ò�������RSA֤��DN��ǩ</p>
 * <p>4��Detached��ժҪ��detachedVerifyHash��:ʹ�ù���RSA֤��DN��ǩ</p>
 * <p>5��Detached��ժҪ��detachedVerifyHash��:ʹ������RSA֤��SN��ǩ</p>
 * <p>6��Detached��ժҪ��detachedVerifyHash��:ʹ������RSA֤��SN��ǩ</p>
 * <p>7��Detached��ժҪ��detachedVerifyHash��:ʹ�ò�������RSA֤��SN��ǩ</p>
 * <p>8��Detached��ժҪ��detachedVerifyHash��:ʹ�ù���RSA֤��SN��ǩ</p>
 * <p>9��Detached��ժҪ��detachedVerifyHash��:ʹ������RSA֤��Bankcode��ǩ</p>
 * <p>10��Detached��ժҪ��detachedVerifyHash��:ʹ������RSA֤��Bankcode��ǩ</p>
 * <p>11��Detached��ժҪ��detachedVerifyHash��:ʹ�ò�������RSA֤��Bankcode��ǩ</p>
 * <p>12��Detached��ժҪ��detachedVerifyHash��:ʹ�ù���RSA֤��Bankcode��ǩ</p>
 * <p>13��Detached��ժҪ��detachedVerifyHash��:ʹ������SM2֤��DN��ǩ</p>
 * <p>14��Detached��ժҪ��detachedVerifyHash��:ʹ������SM2֤��DN��ǩ</p>
 * <p>15��Detached��ժҪ��detachedVerifyHash��:ʹ�ù���SM2֤��DN��ǩ</p>
 * <p>16��Detached��ժҪ��detachedVerifyHash��:ʹ������SM2֤��SN��ǩ</p>
 * <p>17��Detached��ժҪ��detachedVerifyHash��:ʹ������SM2֤��SN��ǩ</p>
 * <p>18��Detached��ժҪ��detachedVerifyHash��:ʹ�ù���SM2֤��SN��ǩ</p>
 * <p>19��Detached��ժҪ��detachedVerifyHash��:ʹ������SM2֤��Bankcode��ǩ</p>
 * <p>20��Detached��ժҪ��detachedVerifyHash��:ʹ������SM2֤��Bankcode��ǩ</p>
 * <p>21��Detached��ժҪ��detachedVerifyHash��:ʹ�ù���SM2֤��Bankcode��ǩ</p>
 * <p>22��Detached��ժҪ��detachedVerifyHash��:ԭ��Ϊ�ջ�null</p>
 * <p>23��Detached��ժҪ��detachedVerifyHash��:����Ϊ�ջ�null</p>
 * <p>24��Detached��ժҪ��detachedVerifyHash��:���Ĵ۸�</p>
 */
public class TestDeatachedVerifyHash {
    static String ip, port, password;
    static String host, sftp_port, sftp_password, sftp_user;

    NetSignServerInit init = new NetSignServerInit();
    UpkiAgent agent;
    SFTPFile tmp = new SFTPFile();

    {
        // ����netsignconfig.properties�����ļ�����ȡ������Ϣ,confpath=null ʹ��Ĭ��·��
        Map<String, String> map = ParseFile.parseProperties(null);
        ip = map.get("ServerIP");
        port = map.get("ServerPortPBC2G");
        password = map.get("APIPassword");
        host = map.get("sftp_ip");
        sftp_port = map.get("sftp_port");
        sftp_user = map.get("sftp_user");
        sftp_password = map.get("sftp_password");

        agent = init.upkiStart(ip, port, password, true, 20);
        tmp.downFile(sftp_user, host, sftp_port, sftp_password, ParameterUtil.sftpkeystorepath,
                ParameterUtil.keystorepath);
        System.out.println("NetSignServerInit OK");
    }

    /**
     * Detached��ժҪ��detachedVerifyHash��:ʹ������RSA֤��DN��ǩ
     *
     * @param dn  ֤��DN
     * @param alg ժҪ�㷨
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "normal-rsa-dn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_01(String dn, String alg) {
        System.out.println("Detached��ժҪ��detachedVerifyHash��:ʹ������RSA֤��DN��ǩ");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("DetachedǩժҪʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("DetachedǩժҪʧ�ܣ�" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1.getResults() == null || upkiResult1.getReturnCode() != 0) {
                Assert.fail("Detached��ժҪʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("DetachedǩժҪʧ�ܣ�" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Detached��ժҪ��detachedVerifyHash��:ʹ������RSA֤��DN��ǩ
     *
     * @param dn  ֤��DN
     * @param alg ժҪ�㷨
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "revoke-rsa-dn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_02(String dn, String alg) {
        System.out.println("Detached��ժҪ��detachedVerifyHash��:ʹ������RSA֤��DN��ǩ");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;

        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("DetachedǩժҪʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("DetachedǩժҪʧ�ܣ�" + e.getMessage() + upkiResult.getReturnCode());
        }

        try {

            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1.getReturnCode() != -100108) {
                if (!"C=CN,O=infosec,OU=test3,CN=C020revokeMatchingAnyCrlfbd".equals(dn) && !("C=CN,O=infosec," +
                        "CN=C020revokedNocrlfile").equals(dn)) {
                    Assert.fail("Detached��ժҪʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
            }
        } catch (Exception e) {
            Assert.fail("Detached��ժҪʧ�ܣ�" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Detached��ժҪ��detachedVerifyHash��:ʹ�ò�������RSA֤��DN��ǩ
     *
     * @param dn  ֤��DN
     * @param alg ժҪ�㷨
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "nottrust-rsa-dn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_03(String dn, String alg) {
        System.out.println("Detached��ժҪ��detachedVerifyHash��:ʹ�ò�������RSA֤��DN��ǩ");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("DetachedǩժҪʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("DetachedǩժҪʧ�ܣ�" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            UpkiResult upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1.getReturnCode() != -100124) {
                Assert.fail("Detached��ժҪʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("DetachedǩժҪʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * Detached��ժҪ��detachedVerifyHash��:ʹ�ù���RSA֤��DN��ǩ
     *
     * @param dn  ֤��DN
     * @param alg ժҪ�㷨
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "expire-rsa-dn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_04(String dn, String alg) {
        System.out.println("Detached��ժҪ��detachedVerifyHash��:ʹ�ù���RSA֤��DN��ǩ");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("DetachedǩժҪʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("DetachedǩժҪʧ�ܣ�" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1 == null || upkiResult1.getReturnCode() != -100106) {
                Assert.fail("Detached��ժҪʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("DetachedǩժҪʧ�ܣ�" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Detached��ժҪ��detachedVerifyHash��:ʹ������RSA֤��SN��ǩ
     *
     * @param sn  ֤��SN
     * @param alg ժҪ�㷨
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "normal-rsa-sn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_05(String sn, String alg) {
        System.out.println("Detached��ժҪ��detachedVerifyHash��:ʹ������RSA֤��SN��ǩ");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, sn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("DetachedǩժҪʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("DetachedǩժҪʧ�ܣ�" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1 == null || upkiResult1.getReturnCode() != 0) {
                Assert.fail("Detached��ժҪʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("DetachedǩժҪʧ�ܣ�" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Detached��ժҪ��detachedVerifyHash��:ʹ������RSA֤��SN��ǩ
     *
     * @param sn  ֤��SN
     * @param alg ժҪ�㷨
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "revoke-rsa-sn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_06(String sn, String alg) {
        System.out.println("Detached��ժҪ��detachedVerifyHash��:ʹ������RSA֤��SN��ǩ");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;

        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, sn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("DetachedǩժҪʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("DetachedǩժҪʧ�ܣ�" + e.getMessage() + upkiResult.getReturnCode());
        }

        try {

            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1.getReturnCode() != -100108) {
                if (!"0219373e13cf29".equals(sn) && !("012c12835bad69").equals(sn)) {
                    Assert.fail("Detached��ժҪʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
            }
        } catch (Exception e) {
            Assert.fail("Detached��ժҪʧ�ܣ�" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Detached��ժҪ��detachedVerifyHash��:ʹ�ò�������RSA֤��SN��ǩ
     *
     * @param sn  ֤��SN
     * @param alg ժҪ�㷨
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "nottrust-rsa-sn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_07(String sn, String alg) {
        System.out.println("Detached��ժҪ��detachedVerifyHash��:ʹ�ò�������RSA֤��SN��ǩ");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        String digestData = null;
        String pSignData;
        try {
            if (sn.equals("50e66bcca4")) {
                return;
            }
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, sn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("DetachedǩժҪʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("DetachedǩժҪʧ�ܣ�" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            UpkiResult upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1.getReturnCode() != -100124) {
                if (!"50e66bcca4".equals(sn)) {
                    Assert.fail("Detached��ժҪʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
            }
        } catch (Exception e) {
            Assert.fail("DetachedǩժҪʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * Detached��ժҪ��detachedVerifyHash��:ʹ�ù���RSA֤��SN��ǩ
     *
     * @param sn  ֤��SN
     * @param alg ժҪ�㷨
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "expire-rsa-sn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_08(String sn, String alg) {
        System.out.println("Detached��ժҪ��detachedVerifyHash��:ʹ�ù���RSA֤��SN��ǩ");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, sn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("DetachedǩժҪʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("DetachedǩժҪʧ�ܣ�" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1 == null || upkiResult1.getReturnCode() != -100106) {
                Assert.fail("Detached��ժҪʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("DetachedǩժҪʧ�ܣ�" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Detached��ժҪ��detachedVerifyHash��:ʹ������RSA֤��Bankcode��ǩ
     *
     * @param bankcode ֤��Bankcode
     * @param alg      ժҪ�㷨
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "normal-rsa-bankcode-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_09(String bankcode, String alg) {
        System.out.println("Detached��ժҪ��detachedVerifyHash��:ʹ������RSA֤��Bankcode��ǩ");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, bankcode, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("DetachedǩժҪʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("DetachedǩժҪʧ�ܣ�" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1 == null || upkiResult1.getReturnCode() != 0) {
                Assert.fail("Detached��ժҪʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("DetachedǩժҪʧ�ܣ�" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Detached��ժҪ��detachedVerifyHash��:ʹ������RSA֤��Bankcode��ǩ
     *
     * @param bankcode ֤��Bankcode
     * @param alg      ժҪ�㷨
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "revoke-rsa-bankcode-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_10(String bankcode, String alg) {
        System.out.println("Detached��ժҪ��detachedVerifyHash��:ʹ������RSA֤��Bankcode��ǩ");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;

        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, bankcode, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("DetachedǩժҪʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("DetachedǩժҪʧ�ܣ�" + e.getMessage() + upkiResult.getReturnCode());
        }

        try {

            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1.getReturnCode() != -100108) {
                if (!"MatchingAnyCrlfbd".equals(bankcode) && !("C020revokeMatchingAnyCrlfbd").equals(bankcode) && !(
                        "C020revokedNocrlfile").equals(bankcode)) {
                    Assert.fail("Detached��ժҪʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
            }
        } catch (Exception e) {
            Assert.fail("Detached��ժҪʧ�ܣ�" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Detached��ժҪ��detachedVerifyHash��:ʹ�ò�������RSA֤��Bankcode��ǩ
     *
     * @param bankcode ֤��Bankcode
     * @param alg      ժҪ�㷨
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "nottrust-rsa-bankcode-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_11(String bankcode, String alg) {
        System.out.println("Detached��ժҪ��detachedVerifyHash��:ʹ�ò�������RSA֤��Bankcode��ǩ");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, bankcode, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("DetachedǩժҪʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("DetachedǩժҪʧ�ܣ�" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            UpkiResult upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1.getReturnCode() != -100124) {
                Assert.fail("Detached��ժҪʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("DetachedǩժҪʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * Detached��ժҪ��detachedVerifyHash��:ʹ�ù���RSA֤��Bankcode��ǩ
     *
     * @param bankcode ֤��Bankcode
     * @param alg      ժҪ�㷨
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "expire-rsa-bankcode-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_12(String bankcode, String alg) {
        System.out.println("Detached��ժҪ��detachedVerifyHash��:ʹ�ù���RSA֤��Bankcode��ǩ");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, bankcode, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("DetachedǩժҪʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("DetachedǩժҪʧ�ܣ�" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1 == null || upkiResult1.getReturnCode() != -100106) {
                Assert.fail("Detached��ժҪʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("DetachedǩժҪʧ�ܣ�" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Detached��ժҪ��detachedVerifyHash��:ʹ������SM2֤��DN��ǩ
     *
     * @param dn  ֤��DN
     * @param alg ժҪ�㷨
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "normal-sm2-dn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_13(String dn, String alg) {
        System.out.println("Detached��ժҪ��detachedVerifyHash��:ʹ������SM2֤��DN��ǩ");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                if (upkiResult.getReturnCode() != -100004 && !"SHA1".equals(alg)) {
                    Assert.fail("DetachedǩժҪʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                return;
            }
        } catch (Exception e) {
            Assert.fail("DetachedǩժҪʧ�ܣ�" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1.getResults() == null || upkiResult1.getReturnCode() != 0) {
                if (upkiResult1.getReturnCode() != -100129) {
                    Assert.fail("Detached��ժҪʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                Reporter.log("Detached��ժҪ��DetachedVerifyHash��������֤����ǩʱ��֧��SHA256�㷨");
            }
        } catch (Exception e) {
            Assert.fail("DetachedǩժҪʧ�ܣ�" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Detached��ժҪ��detachedVerifyHash��:ʹ������SM2֤��DN��ǩ
     *
     * @param dn  ֤��DN
     * @param alg ժҪ�㷨
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "revoke-sm2-dn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_14(String dn, String alg) {
        System.out.println("Detached��ժҪ��detachedVerifyHash��:ʹ������SM2֤��DN��ǩ");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;

        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                if (upkiResult.getReturnCode() != -100004 && !"SHA1".equals(alg)) {
                    Assert.fail("DetachedǩժҪʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                return;
            }
        } catch (Exception e) {
            Assert.fail("DetachedǩժҪʧ�ܣ�" + e.getMessage() + upkiResult.getReturnCode());
        }

        try {

            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1.getReturnCode() != -100108) {
                Assert.fail("Detached��ժҪʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Detached��ժҪʧ�ܣ�" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Detached��ժҪ��detachedVerifyHash��:ʹ�ù���SM2֤��DN��ǩ
     *
     * @param dn  ֤��DN
     * @param alg ժҪ�㷨
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "expire-sm2-dn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_15(String dn, String alg) {
        System.out.println("Detached��ժҪ��detachedVerifyHash��:ʹ�ù���SM2֤��DN��ǩ");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                if (upkiResult.getReturnCode() != -100004 && !"SHA1".equals(alg)) {
                    Assert.fail("DetachedǩժҪʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                return;
            }
        } catch (Exception e) {
            Assert.fail("DetachedǩժҪʧ�ܣ�" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1 == null || upkiResult1.getReturnCode() != -100106) {
                Assert.fail("Detached��ժҪʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("DetachedǩժҪʧ�ܣ�" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Detached��ժҪ��detachedVerifyHash��:ʹ������SM2֤��SN��ǩ
     *
     * @param sn  ֤��SN
     * @param alg ժҪ�㷨
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "normal-sm2-sn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_16(String sn, String alg) {
        System.out.println("Detached��ժҪ��detachedVerifyHash��:ʹ������SM2֤��SN��ǩ");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, sn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                if (upkiResult.getReturnCode() != -100004 && !"SHA1".equals(alg)) {
                    Assert.fail("DetachedǩժҪʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                return;
            }
        } catch (Exception e) {
            Assert.fail("DetachedǩժҪʧ�ܣ�" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1 == null || upkiResult1.getReturnCode() != 0) {
                if (upkiResult1.getReturnCode() != -100129) {
                    Assert.fail("Detached��ժҪʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                Reporter.log("Detached��ժҪ��DetachedVerifyHash��������֤����ǩʱ��֧��SHA256�㷨");
            }
        } catch (Exception e) {
            Assert.fail("DetachedǩժҪʧ�ܣ�" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Detached��ժҪ��detachedVerifyHash��:ʹ������SM2֤��SN��ǩ
     *
     * @param sn  ֤��SN
     * @param alg ժҪ�㷨
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "revoke-sm2-sn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_17(String sn, String alg) {
        System.out.println("Detached��ժҪ��detachedVerifyHash��:ʹ������SM2֤��SN��ǩ");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;

        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, sn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                if (upkiResult.getReturnCode() != -100004 && !"SHA1".equals(alg)) {
                    Assert.fail("DetachedǩժҪʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                return;
            }
        } catch (Exception e) {
            Assert.fail("DetachedǩժҪʧ�ܣ�" + e.getMessage() + upkiResult.getReturnCode());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1.getReturnCode() != -100108) {
                Assert.fail("Detached��ժҪʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Detached��ժҪʧ�ܣ�" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Detached��ժҪ��detachedVerifyHash��:ʹ�ù���SM2֤��SN��ǩ
     *
     * @param sn  ֤��SN
     * @param alg ժҪ�㷨
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "expire-sm2-sn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_18(String sn, String alg) {
        System.out.println("Detached��ժҪ��detachedVerifyHash��:ʹ�ù���SM2֤��SN��ǩ");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, sn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                if (upkiResult.getReturnCode() != -100004 && !"SHA1".equals(alg)) {
                    Assert.fail("DetachedǩժҪʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                return;
            }
        } catch (Exception e) {
            Assert.fail("DetachedǩժҪʧ�ܣ�" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1 == null || upkiResult1.getReturnCode() != -100106) {
                Assert.fail("Detached��ժҪʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (
                Exception e) {
            Assert.fail("DetachedǩժҪʧ�ܣ�" + e.getMessage() + upkiResult1.getReturnCode());
        }

    }

    /**
     * Detached��ժҪ��detachedVerifyHash��:ʹ������SM2֤��Bankcode��ǩ
     *
     * @param bankcode ֤��Bankcode
     * @param alg      ժҪ�㷨
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "normal-sm2-bankcode-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_19(String bankcode, String alg) {
        System.out.println("Detached��ժҪ��detachedVerifyHash��:ʹ������SM2֤��Bankcode��ǩ");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, bankcode, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                if (upkiResult.getReturnCode() != -100004 && !"SHA1".equals(alg)) {
                    Assert.fail("DetachedǩժҪʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                return;
            }
        } catch (Exception e) {
            Assert.fail("DetachedǩժҪʧ�ܣ�" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1 == null || upkiResult1.getReturnCode() != 0) {
                if (upkiResult1.getReturnCode() != -100129) {
                    Assert.fail("Detached��ժҪʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                Reporter.log("Detached��ժҪ��DetachedVerifyHash��������֤����ǩʱ��֧��SHA256�㷨");
            }
        } catch (Exception e) {
            Assert.fail("DetachedǩժҪʧ�ܣ�" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Detached��ժҪ��detachedVerifyHash��:ʹ������SM2֤��Bankcode��ǩ
     *
     * @param bankcode ֤��Bankcode
     * @param alg      ժҪ�㷨
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "revoke-sm2-bankcode-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_20(String bankcode, String alg) {
        System.out.println("Detached��ժҪ��detachedVerifyHash��:ʹ������SM2֤��Bankcode��ǩ");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;

        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, bankcode, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                if (upkiResult.getReturnCode() != -100004 && !"SHA1".equals(alg)) {
                    Assert.fail("DetachedǩժҪʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                return;
            }
        } catch (Exception e) {
            Assert.fail("DetachedǩժҪʧ�ܣ�" + e.getMessage() + upkiResult.getReturnCode());
        }

        try {

            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1.getReturnCode() != -100108) {
                if (upkiResult1.getReturnCode() != -100130 && "SHA1".equals(alg)) {
                    Assert.fail("Detached��ժҪʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                Reporter.log("Detached��ժҪ��DetachedVerifyHash��������֤����ǩʱ��֧��SHA1�㷨");
            }
        } catch (Exception e) {
            Assert.fail("Detached��ժҪʧ�ܣ�" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Detached��ժҪ��detachedVerifyHash��:ʹ�ù���SM2֤��Bankcode��ǩ
     *
     * @param bankcode ֤��Bankcode
     * @param alg      ժҪ�㷨
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "expire-sm2-bankcode-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_21(String bankcode, String alg) {
        System.out.println("Detached��ժҪ��detachedVerifyHash��:ʹ�ù���SM2֤��Bankcode��ǩ");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, bankcode, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                if (upkiResult.getReturnCode() != -100004 && !"SHA1".equals(alg)) {
                    Assert.fail("DetachedǩժҪʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                return;
            }
        } catch (Exception e) {
            Assert.fail("DetachedǩժҪʧ�ܣ�" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1 == null || upkiResult1.getReturnCode() != -100106) {
                Assert.fail("Detached��ժҪʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("DetachedǩժҪʧ�ܣ�" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Detached��ժҪ��detachedVerifyHash��:ԭ��Ϊ�ջ�null
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_22(String str) {
        System.out.println("Detached��ժҪ��detachedVerifyHash��:ԭ��Ϊ�ջ�null");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        String alg = "SHA1";
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("DetachedǩժҪʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("DetachedǩժҪʧ�ܣ�" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.detachedVerifyHash(str, pSignData);
            if (upkiResult1.getReturnCode() != -1011 && upkiResult1.getReturnCode() != -100101) {
                Assert.fail("Detached��ժҪʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Detached��ժҪʧ�ܣ�" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Detached��ժҪ��detachedVerifyHash��:����Ϊ�ջ�null
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_23(String pSignData) {
        System.out.println("Detached��ժҪ��detachedVerifyHash��:����Ϊ�ջ�null");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        String alg = "SHA1";
        UpkiResult upkiResult1 = null;
        String digestData = null;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1.getReturnCode() != -1011 && upkiResult1.getReturnCode() != -100004) {
                Assert.fail("Detached��ժҪʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Detached��ժҪʧ�ܣ�" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }


    /**
     * Detached��ժҪ��detachedVerifyHash��:���Ĵ۸�
     */
    @Test(groups = "abcjew.detachedverifyhash.normal")
    public void testDetachedVerifyHash_24() {
        System.out.println("Detached��ժҪ��detachedVerifyHash��:���Ĵ۸�");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        String alg = "SHA1";
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("DetachedǩժҪʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("DetachedǩժҪʧ�ܣ�" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            pSignData = Utils.modifyData(pSignData, 5, 10, "abcde");
            upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1.getReturnCode() != -1011) {
                Assert.fail("Detached��ժҪʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Detached��ժҪʧ�ܣ�" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }
}
