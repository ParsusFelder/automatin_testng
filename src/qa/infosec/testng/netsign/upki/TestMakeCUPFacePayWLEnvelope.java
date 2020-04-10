package qa.infosec.testng.netsign.upki;

import cn.com.infosec.netsign.agent.PBCAgent2G;
import cn.com.infosec.netsign.agent.UpkiAgent;
import qa.infosec.testng.netsign.dataprovider.util.ParameterUtil;
import qa.infosec.testng.netsign.dataprovider.util.ParseFile;
import qa.infosec.testng.netsign.dataprovider.util.SFTPFile;
import qa.infosec.testng.netsign.init.NetSignServerInit;

import java.util.Map;

/**
 * @author zhaoyongzhi
 * @ClassName: TestMakeCUPFacePayWLEnvelope
 * @date 2020-03-02 18:21
 * @Description:
 * <p>用例覆盖点：</p>
 * <p>1）制作刷脸支付数字信封,对称密钥类型为SM4/AES</p>
 * <p>2）制作刷脸支付数字信封,对称密钥类型为3DES/DES</p>
 * <p>3）pinCrypto为null,算法类型为SM4/AES</p>
 * <p>4）pinCrypto为null,算法类型为3DES/DES</p>
 * <p>5）pinCrypto密文篡改,对称密钥类型SM4/AES</p>
 * <p>6）pinCrypto密文篡改，对称密钥类型3DES/DES</p>
 * <p>7）iv为null,填充模式为/ECB</p>
 * <p>8）iv为null,填充模式为/CBC/CFB/OFB</p>
 * <p>9）iv 长度错误</p>
 * <p>10）iv 篡改</p>
 * <p>11）iv 解密pin密文所需IV与加密敏感数据所用IV不一致</p>
 * <p>12）pinModeAndPadding 与加密时使用的填充模式不匹配</p>
 * <p>13）pinModeAndPadding 传入为空</p>
 * <p>14）pinModeAndPadding 传入为null</p>
 * <p>15）pinModeAndPadding 传入错误值</p>
 * <p>16）pinModeAndPadding 内容错误</p>
 * <p>17）noPaddingSecret 无需补位的敏感数据，长度非算法分组长度整数倍，算法类型为DES/3DES</p>
 * <p>18）noPaddingSecret 无需补位的敏感数据，长度非算法分组长度整数倍，算法类型为AES/SM4</p>
 * <p>19）noPaddingSecret 传入为null</p>
 * <p>20）paddingSecret 长度非算法分组长度整数倍，算法类型为3DES/DES</p>
 * <p>21）paddingSecret 长度非算法分组长度整数倍，算法类型为AES/SM4</p>
 * <p>22）paddingSecret 传入为null</p>
 * <p>23）paddingSecret 长度非算法分组长度整数倍,填充模式为/CBC/NoPadding</p>
 * <p>24）modeAndPadding 加密填充模式为空</p>
 * <p>25）modeAndPadding 加密填充模式为null</p>
 * <p>26）encDN 正确DN，对称算法类型为DES/3DES</p>
 * <p>27）encDN 正确DN，对称算法类型为AES/SM4</p>
 * <p>28）encDN DN不存在</p>
 * <p>29）encDN DN为空</p>
 * <p>30）encDN DN为null</p>
 */
public class TestMakeCUPFacePayWLEnvelope {
    static String ip, port, password;
    static String host, sftp_port, sftp_password, sftp_user;

    NetSignServerInit init = new NetSignServerInit();
    UpkiAgent agent;
    PBCAgent2G pbc2g;
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
        pbc2g = init.start(ip,port,password,true,20);
        tmp.downFile(sftp_user, host, sftp_port, sftp_password, ParameterUtil.sftpsymmpath,
                ParameterUtil.localsymmpath);
        System.out.println("NetSignServerInit OK");
    }

}
