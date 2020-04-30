package qa.infosec.testng.netsign.upki;

import cn.com.infosec.netsign.agent.UpkiAgent;
import cn.com.infosec.netsign.agent.UpkiResult;
import cn.com.infosec.netsign.json.JsonValueString;
import org.testng.Assert;
import org.testng.Reporter;
import org.testng.annotations.Test;
import qa.infosec.testng.netsign.dataprovider.NetSignDataProvider;
import qa.infosec.testng.netsign.dataprovider.util.ParameterUtil;
import qa.infosec.testng.netsign.dataprovider.util.ParseFile;
import qa.infosec.testng.netsign.dataprovider.util.SFTPFile;
import qa.infosec.testng.netsign.init.NetSignServerInit;

import java.util.Map;
import java.util.Random;

import static qa.infosec.testng.netsign.dataprovider.util.JsonMessage.*;

/**
 * @author zhaoyongzhi
 * @ClassName: TestCUPCQPDecryptAndVerify
 * @date 2020-04-26 18:17
 * @Description: ���������ܲ���ǩ
 * <p>�������ǵ㣺</p>
 * <p>1��</p>
 * <p>2��</p>
 * <p>3��</p>
 * <p>4��</p>
 * <p>5��</p>
 */
@Test(groups = "abcjew.cupcqpdecryptandverify")
public class TestCUPCQPDecryptAndVerify {
    static String ip, port, password;
    static String host, sftp_port, sftp_password, sftp_user;
    Random random = new Random();

    NetSignServerInit init = new NetSignServerInit();
    UpkiAgent agent;
    SFTPFile tmp = new SFTPFile();
    JsonValueString jsonValue = new JsonValueString();

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
        tmp.downFile(sftp_user, host, sftp_port, sftp_password, ParameterUtil.sftpdetailpath,
                ParameterUtil.localdetailpath);
        System.out.println("NetSignServerInit OK");
    }

    /**
     * ���������ܲ���ǩ��ʹ������״̬֤��DN���ܲ���ǩ
     *
     * @param dn ����״̬֤��DN
     */
    @Test(groups = "abcjew.cupcqpdecryptandverify", dataProvider = "normal-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPCQPDecryptAndVerify_01(String dn) {
        String jsonMessage = CUPCQPEncAndsignMessage;
        // ���ܲ�ǩ���õ�����
        UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonMessage, dn, dn);
        String enc_text = upkiResult.getResults().get("enc_text").toString();
        try {
            UpkiResult upkiResult1 = agent.CUPCQPDecryptAndVerify(enc_text, dn, dn);
            if (upkiResult1.getReturnCode() != 0 || !upkiResult1.getBoolResult()) {
                Assert.fail("���������ܲ���ǩʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
            System.out.println("���������ܲ���ǩ��ʹ������״̬֤��DN���ܲ���ǩ��DN:[" + dn + "] ִ�гɹ�");
        } catch (Exception e) {
            Assert.fail("���������ܲ���ǩʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ���ǩ��ʹ������״̬֤��SN���ܲ���ǩ
     *
     * @param sn ����״̬֤��SN
     */
    @Test(groups = "abcjew.cupcqpdecryptandverify", dataProvider = "normal-sn", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPCQPDecryptAndVerify_02(String sn) {
        String jsonMessage = CUPCQPEncAndsignMessage;
        UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonMessage, sn, sn);
        String enc_text = upkiResult.getResults().get("enc_text").toString();
        // ���ܲ�ǩ���õ�����
        try {
            UpkiResult upkiResult1 = agent.CUPCQPDecryptAndVerify(enc_text, sn, sn);
            if (upkiResult1.getReturnCode() != 0 || !upkiResult1.getBoolResult()) {
                if (upkiResult1.getReturnCode() != -100224) {
                    Assert.fail("���������ܲ���ǩʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                Reporter.log("���������ܲ���ǩ(CUPCQPDecryptAndVerify)����ǩ��֤�鲻֧��ʹ��֤��SN");
            }
            System.out.println("���������ܲ���ǩ��ʹ������״̬֤��SN���ܲ���ǩ��SN:[" + sn + "]ִ�гɹ�");
        } catch (Exception e) {
            Assert.fail("���������ܲ���ǩʧ��(CUPCQPDecryptAndVerify)��" + e.getMessage());
        }
    }

    /**
     * ���������ܲ���ǩ��ʹ������״̬֤��Bankcode���ܲ���ǩ
     *
     * @param bankcode ����״̬֤��Bankcode
     */
    @Test(groups = "abcjew.cupcqpdecryptandverify", dataProvider = "normal-bankcode", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPCQPDecryptAndVerify_03(String bankcode) {
        String jsonMessage = CUPCQPEncAndsignMessage;
        // ���ܲ�ǩ���õ�����
        String enc_text = null;
        UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonMessage, bankcode, bankcode);
        enc_text = upkiResult.getResults().get("enc_text").toString();
        try {
            UpkiResult upkiResult1 = agent.CUPCQPDecryptAndVerify(enc_text, bankcode, bankcode);
            if (upkiResult1.getReturnCode() != 0 || !upkiResult1.getBoolResult()) {
                Assert.fail("���������ܲ���ǩʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
            System.out.println("���������ܲ���ǩ��ʹ������״̬֤��Bankcode���ܲ���ǩ��Bankcode:[" + bankcode + "] ִ�гɹ�");
        } catch (Exception e) {
            Assert.fail("���������ܲ���ǩʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ���ǩ��ʹ������״̬֤��DN���ܲ���ǩ
     *
     * @param dn ����״̬֤��DN
     */
    @Test(groups = "abcjew.cupcqpdecryptandverify", dataProvider = "revoke-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPCQPDecryptAndVerify_04(String dn) {
        String jsonMessage = CUPCQPEncAndsignMessage;
        // ���ܲ�ǩ���õ�����
        UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonMessage, dn, dn);
        String enc_text = upkiResult.getResults().get("enc_text").toString();
        if ("C=CN,O=infosec,OU=test3,CN=C020revokeMatchingAnyCrlfbd".equals(dn) || ("C=CN,O=infosec," +
                "CN=C020revokedNocrlfile").equals(dn)) {
            return;
        }
        try {
            UpkiResult upkiResult1 = agent.CUPCQPDecryptAndVerify(enc_text, dn, dn);
            if (upkiResult1.getReturnCode() != -100108 || upkiResult1.getBoolResult()) {
                Assert.fail("���������ܲ���ǩʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
            System.out.println("���������ܲ���ǩ��ʹ������״̬֤��DN���ܲ���ǩ��DN:[" + dn + "] ִ�гɹ�");
        } catch (Exception e) {
            Assert.fail("���������ܲ���ǩʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ���ǩ��ʹ������״̬֤��SN���ܲ���ǩ
     *
     * @param sn ����״̬֤��SN
     */
    @Test(groups = "abcjew.cupcqpdecryptandverify", dataProvider = "revoke-sn", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPCQPDecryptAndVerify_05(String sn) {
        String jsonMessage = CUPCQPEncAndsignMessage;
        // ���ܲ�ǩ���õ�����
        UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonMessage, sn, sn);
        String enc_text = upkiResult.getResults().get("enc_text").toString();
        try {
            UpkiResult upkiResult1 = agent.CUPCQPDecryptAndVerify(enc_text, sn, sn);
            if (upkiResult1.getReturnCode() != -100108 || upkiResult1.getBoolResult()) {
                if (upkiResult1.getReturnCode() != -100224) {
                    Assert.fail("���������ܲ���ǩʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                Reporter.log("���������ܲ���ǩ(CUPCQPDecryptAndVerify)����ǩ��֤�鲻֧��ʹ��֤��SN");
            }
            System.out.println("���������ܲ���ǩ��ʹ������״̬֤��SN���ܲ���ǩ��SN:[" + sn + "] ִ�гɹ�");
        } catch (Exception e) {
            Assert.fail("���������ܲ���ǩʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ���ǩ��ʹ������״̬֤��Bankcode���ܲ���ǩ
     *
     * @param bankcode ����״̬֤��Bankcode
     */
    @Test(groups = "abcjew.cupcqpdecryptandverify", dataProvider = "revoke-bankcode", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPCQPDecryptAndVerify_06(String bankcode) {
        String jsonMessage = CUPCQPEncAndsignMessage;
        // ���ܲ�ǩ���õ�����
        UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonMessage, bankcode, bankcode);
        String enc_text = upkiResult.getResults().get("enc_text").toString();
        if ("MatchingAnyCrlfbd".equals(bankcode) || ("C020revokeMatchingAnyCrlfbd").equals(bankcode) ||
                "C020revokedNocrlfile".equals(bankcode)) {
            return;
        }
        try {
            UpkiResult upkiResult1 = agent.CUPCQPDecryptAndVerify(enc_text, bankcode, bankcode);
            if (upkiResult1.getReturnCode() != -100108 || upkiResult1.getBoolResult()) {
                Assert.fail("���������ܲ���ǩʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
            System.out.println("���������ܲ���ǩ��ʹ������״̬֤��Bankcode���ܲ���ǩ��Bankcode:[" + bankcode + "] ִ�гɹ�");
        } catch (Exception e) {
            Assert.fail("���������ܲ���ǩʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ���ǩ��ʹ�ù���״̬֤��DN���ܲ���ǩ
     *
     * @param dn ����״̬֤��DN
     */
    @Test(groups = "abcjew.cupcqpdecryptandverify", dataProvider = "expire-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPCQPDecryptAndVerify_07(String dn) {
        String jsonMessage = CUPCQPEncAndsignMessage;
        // ���ܲ�ǩ���õ�����
        UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonMessage, dn, dn);
        String enc_text = upkiResult.getResults().get("enc_text").toString();
        try {
            UpkiResult upkiResult1 = agent.CUPCQPDecryptAndVerify(enc_text, dn, dn);
            if (upkiResult1.getReturnCode() != -100106 || upkiResult1.getBoolResult()) {
                Assert.fail("���������ܲ���ǩʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
            System.out.println("���������ܲ���ǩ��ʹ�ù���״̬֤��DN���ܲ���ǩ��DN:[" + dn + "] ִ�гɹ�");
        } catch (Exception e) {
            Assert.fail("���������ܲ���ǩʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ���ǩ��ʹ�ù���״̬֤��SN���ܲ���ǩ
     *
     * @param sn ����״̬֤��SN
     */
    @Test(groups = "abcjew.cupcqpdecryptandverify", dataProvider = "expire-sn", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPCQPDecryptAndVerify_08(String sn) {
        String jsonMessage = CUPCQPEncAndsignMessage;
        // ���ܲ�ǩ���õ�����
        UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonMessage, sn, sn);
        String enc_text = upkiResult.getResults().get("enc_text").toString();
        try {
            UpkiResult upkiResult1 = agent.CUPCQPDecryptAndVerify(enc_text, sn, sn);
            if (upkiResult1.getReturnCode() != -100106 || upkiResult1.getBoolResult()) {
                if (upkiResult1.getReturnCode() != -100224) {
                    Assert.fail("���������ܲ���ǩʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                Reporter.log("���������ܲ���ǩ(CUPCQPDecryptAndVerify)����ǩ��֤�鲻֧��ʹ��֤��SN");
            }
            System.out.println("���������ܲ���ǩ��ʹ�ù���״̬֤��SN���ܲ���ǩ��SN:[" + sn + "] ִ�гɹ�");
        } catch (Exception e) {
            Assert.fail("���������ܲ���ǩʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ���ǩ��ʹ�ù���״̬֤��Bankcode���ܲ���ǩ
     *
     * @param bankcode ����״̬֤��Bankcode
     */
    @Test(groups = "abcjew.cupcqpdecryptandverify", dataProvider = "expire-bankcode", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPCQPDecryptAndVerify_09(String bankcode) {
        String jsonMessage = CUPCQPEncAndsignMessage;
        // ���ܲ�ǩ���õ�����
        UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonMessage, bankcode, bankcode);
        String enc_text = upkiResult.getResults().get("enc_text").toString();

        try {
            UpkiResult upkiResult1 = agent.CUPCQPDecryptAndVerify(enc_text, bankcode, bankcode);
            if (upkiResult1.getReturnCode() != -100106 || upkiResult1.getBoolResult()) {
                Assert.fail("���������ܲ���ǩʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
            System.out.println("���������ܲ���ǩ��ʹ�ù���״̬֤��Bankcode���ܲ���ǩ��Bankcode:[" + bankcode + "] ִ�гɹ�");
        } catch (Exception e) {
            Assert.fail("���������ܲ���ǩʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ���ǩ������Ϊ�ջ�null
     *
     * @param enc_text ����
     */
    @Test(groups = "abcjew.cupcqpdecryptandverify", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPCQPDecryptAndVerify_10(String enc_text) {
        String jsonMessage = CUPCQPEncAndsignMessage;
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=SS019normal";

        try {
            UpkiResult upkiResult1 = agent.CUPCQPDecryptAndVerify(enc_text, dn, dn);
            if (upkiResult1.getReturnCode() != -1026) {
                Assert.fail("���������ܲ���ǩʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
            System.out.println("���������ܲ���ǩ������Ϊ�ջ�null������:[" + enc_text + "] ִ�гɹ�");
        } catch (Exception e) {
            Assert.fail("���������ܲ���ǩʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ���ǩ������֤��Ϊ�ջ�null
     *
     * @param encDn ����֤��DN
     */
    @Test(groups = "abcjew.cupcqpdecryptandverify", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPCQPDecryptAndVerify_11(String encDn) {
        String jsonMessage = CUPCQPEncAndsignMessage;
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=SS019normal";
        // ���ܲ�ǩ���õ�����
        UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonMessage, dn, dn);
        String enc_text = upkiResult.getResults().get("enc_text").toString();

        try {
            UpkiResult upkiResult1 = agent.CUPCQPDecryptAndVerify(enc_text, encDn, dn);
            if (upkiResult1.getReturnCode() != -1026 && upkiResult1.getReturnCode() != -100110) {
                Assert.fail("���������ܲ���ǩʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
            System.out.println("���������ܲ���ǩ������֤��Ϊ�ջ�null������:[" + encDn + "] ִ�гɹ�");
        } catch (Exception e) {
            Assert.fail("���������ܲ���ǩʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ���ǩ��ǩ��֤��Ϊ�ջ�null
     *
     * @param signDn ǩ��֤��DN
     */
    @Test(groups = "abcjew.cupcqpdecryptandverify", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPCQPDecryptAndVerify_12(String signDn) {
        String jsonMessage = CUPCQPEncAndsignMessage;
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=SS019normal";
        // ���ܲ�ǩ���õ�����
        UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonMessage, dn, dn);
        String enc_text = upkiResult.getResults().get("enc_text").toString();

        try {
            UpkiResult upkiResult1 = agent.CUPCQPDecryptAndVerify(enc_text, dn, signDn);
            if (upkiResult1.getReturnCode() != -100224) {
                Assert.fail("���������ܲ���ǩʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
            System.out.println("���������ܲ���ǩ������֤��Ϊ�ջ�null������:[" + dn + "] ִ�гɹ�");
        } catch (Exception e) {
            Assert.fail("���������ܲ���ǩʧ�ܣ�" + e.getMessage());
        }
    }

}
