package qa.infosec.testng.netsign.dataprovider.util;

import java.io.FileOutputStream;
import java.io.OutputStream;
import java.util.Properties;

import com.jcraft.jsch.Channel;
import com.jcraft.jsch.ChannelSftp;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.SftpATTRS;

/**
 * 使用SFTP协议对文件操作
 * <p>Title: SFTPFile</p>  
 * <p>Description: </p>  
 * @author maxf  
 * @date 2019年8月14日
 */
public class SFTPFile {
	
	/**
	 * 使用SFTP协议下载指定文件至指定目录
	 * @param sftp_user
	 * @param host
	 * @param port
	 * @param password
	 * @param filename
	 * @param dst
	 */
	public void downFile(String sftp_user, String host, String port, String password, String filename, String dst) {

		Session session = null;
		Channel channel = null;
		ChannelSftp c = null;
		// Map<String, String> sftpDetails = new HashMap<String, String>();
		// 设置主机ip，端口，用户名，密码
		
		try {
			JSch jsch = new JSch();
			int iport = Integer.parseInt(port);
			session = jsch.getSession(sftp_user, host, iport);

			session.setPassword(password);

			Properties config = new Properties();
			config.put("StrictHostKeyChecking", "no");
			session.setConfig(config);// 为Session对象设置properties
			session.setTimeout(300);// 设置timeout时候
			session.connect();// 经由过程Session建树链接

			channel = session.openChannel("sftp");// 打开SFTP通道
			channel.connect();
			c = (ChannelSftp) channel;

			@SuppressWarnings("unused")
			SftpATTRS attr = c.stat(filename);
			//long fileSize = attr.getSize();
			OutputStream out = new FileOutputStream(dst);
			c.get(filename, dst); // 代码段1
			out.close();
		} catch (JSchException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			c.disconnect();
			c.quit();
		}
	}

}
