package burp;


import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import java.awt.*;
import java.awt.event.ItemListener;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JMenuItem;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.table.TableCellRenderer;



public class BurpExtender extends AbstractTableModel implements IBurpExtender, ITab, IHttpListener,IScannerCheck, IMessageEditorController,IContextMenuFactory
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JSplitPane splitPane;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private final List<LogEntry> log = new ArrayList<LogEntry>();//记录原始流量
    private final List<LogEntry> log2 = new ArrayList<LogEntry>();//记录攻击流量
    private final List<LogEntry> log3 = new ArrayList<LogEntry>();//用于展现
    private final List<Request_md5> log4_md5 = new ArrayList<Request_md5>();//用于存放数据包的md5
    private IHttpRequestResponse currentlyDisplayedItem;
    public PrintWriter stdout;
    int switchs = 1; //开关 0关 1开
    int clicks_Repeater=0;//64是监听 0是关闭
    int clicks_Proxy=0;//4是监听 0是关闭
    int conut = 0; //记录条数
    String data_md5_id; //用于判断目前选中的数据包
    public AbstractTableModel model = new MyModel();
    int original_data_len;//记录原始数据包的长度
    int is_int = 1; //开关 0关 1开;//纯数据是否进行-1，-0
    String temp_data; //用于保存临时内容
    int JTextArea_int = 0;//自定义payload开关  0关 1开
    String JTextArea_data_1 = "";//文本域的内容
    int diy_payload_1 = 1;//自定义payload空格编码开关  0关 1开
    int diy_payload_2 = 0;//自定义payload值置空开关  0关 1开
    int select_row = 0;//选中表格的行数
    Table logTable; //第一个表格框
    int is_cookie = -1;//cookie是否要注入，-1关闭 2开启。
    int is_referer = -1;//Referer是否要注入，-1关闭 2开启。
    //只匹配请求头区域中的 Referer 头，静态编译一次，避免每个请求重复编译带来性能消耗
    private static final Pattern REFERER_HEADER_PATTERN = Pattern.compile("(?im)^Referer:[ \\t]*(.*)$");
    String white_URL = "";
    int white_switchs = 0;//白名单开关





    //
    // implement IBurpExtender
    //

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        //输出
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stdout.println("hello mhszed sql!");
        this.stdout.println("你好 欢迎使用 mhszed二开!");
        this.stdout.println("version:1.0");
        this.stdout.println("支持原版:https://github.com/smxiazi/xia_sql/");
        this.stdout.println("我的git链接:https://github.com/mhszed");


        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        // obtain an extension helpers object
        helpers = callbacks.getHelpers();

        // set our extension name
        callbacks.setExtensionName("mhszed SQL V1.0");

        // create our UI
        SwingUtilities.invokeLater(new Runnable()
        {
            @Override
            public void run()
            {

                // main split pane
                splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
                JSplitPane splitPanes = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
                JSplitPane splitPanes_2 = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

                // table of log entries
                logTable = new Table(BurpExtender.this);
                logTable.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
                logTable.getColumnModel().getColumn(3).setPreferredWidth(100);
                logTable.getColumnModel().getColumn(4).setPreferredWidth(350);
                JScrollPane scrollPane = new JScrollPane(logTable); //给列表添加滚动条



                //test
                JPanel jp=new JPanel();
                JLabel jl=new JLabel("==>");    //创建一个标签

                Table_log2 table=new Table_log2(model);
                table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
                table.getColumnModel().getColumn(3).setPreferredWidth(450);
                JScrollPane pane=new JScrollPane(table);//给列表添加滚动条

                jp.add(scrollPane);    //将表格加到面板
                jp.add(jl);    //将标签添加到面板
                jp.add(pane);    //将表格加到面板

                //侧边控制面板
                JPanel jps=new JPanel();
                jps.setLayout(new BoxLayout(jps, BoxLayout.Y_AXIS));

                // ── 插件信息 ──
                JPanel infoPanel = new JPanel(new GridLayout(0, 1));
                infoPanel.setBorder(BorderFactory.createTitledBorder("插件信息"));
                JLabel titleLabel = new JLabel("瞎注 (xia SQL)");
                JLabel verLabel  = new JLabel("版本：V1.0");
                JLabel authorLabel = new JLabel("原作者：算命縖子  二开：mhszed");
                JLabel urlLabel  = new JLabel("原版仓库：https://github.com/smxiazi/xia_sql");
                infoPanel.add(titleLabel);
                infoPanel.add(verLabel);
                infoPanel.add(authorLabel);
                infoPanel.add(urlLabel);

                // ── 扫描开关 ──
                JPanel switchPanel = new JPanel(new GridLayout(0, 1));
                switchPanel.setBorder(BorderFactory.createTitledBorder("扫描设置"));
                JCheckBox chkbox1=new JCheckBox("启动插件", true);
                JCheckBox chkbox2=new JCheckBox("监控Repeater");
                JCheckBox chkbox3=new JCheckBox("监控Proxy");
                JCheckBox chkbox4=new JCheckBox("值是数字则进行-1、-0",true);
                JCheckBox chkbox8=new JCheckBox("测试Cookie");
                JCheckBox chkbox9=new JCheckBox("测试Referer");
                switchPanel.add(chkbox1);
                switchPanel.add(chkbox2);
                switchPanel.add(chkbox3);
                switchPanel.add(chkbox4);
                switchPanel.add(chkbox8);
                switchPanel.add(chkbox9);

                // ── 白名单 ──
                JPanel whitePanel = new JPanel(new GridLayout(0, 1));
                whitePanel.setBorder(BorderFactory.createTitledBorder("白名单"));
                JLabel jls_5=new JLabel("多个域名用英文逗号隔开");
                JTextField textField = new JTextField("填写白名单域名");
                JButton btn3=new JButton("启动白名单");
                whitePanel.add(jls_5);
                whitePanel.add(textField);
                whitePanel.add(btn3);

                // ── 自定义Payload ──
                JPanel payloadPanel = new JPanel(new GridLayout(0, 1));
                payloadPanel.setBorder(BorderFactory.createTitledBorder("自定义Payload"));
                JLabel jls_4=new JLabel("修改后点击下方按钮加载");
                JCheckBox chkbox5=new JCheckBox("自定义payload");
                JCheckBox chkbox6=new JCheckBox("自定义payload中空格url编码",true);
                JCheckBox chkbox7=new JCheckBox("自定义payload中参数值置空");
                JButton btn2=new JButton("加载/重新加载payload");
                payloadPanel.add(jls_4);
                payloadPanel.add(chkbox5);
                payloadPanel.add(chkbox6);
                payloadPanel.add(chkbox7);
                payloadPanel.add(btn2);

                // ── 操作 ──
                JPanel actionPanel = new JPanel(new GridLayout(0, 1));
                actionPanel.setBorder(BorderFactory.createTitledBorder("操作"));
                JButton btn1=new JButton("清空列表");
                actionPanel.add(btn1);

                //自定义payload区
                JPanel jps_2=new JPanel();
                jps_2.setLayout(new GridLayout(1, 1)); //六行一列
                JTextArea jta=new JTextArea("%df' and sleep(3)%23\n'and '1'='1",18,16);

                //读取ini配置文件
                try {
                    BufferedReader in = new BufferedReader(new FileReader("xia_SQL_diy_payload.ini"));
                    String str,str_data="";
                    while ((str = in.readLine()) != null) {
                        str_data += str+"\n";
                    }
                    jta.setText(str_data);
                } catch (IOException e) {
                }

                //jta.setLineWrap(true);    //设置文本域中的文本为自动换行
                jta.setForeground(Color.BLACK);    //设置组件的背景色
                jta.setFont(new Font("楷体",Font.BOLD,16));    //修改字体样式
                jta.setBackground(Color.LIGHT_GRAY);    //设置背景色
                jta.setEditable(false);//不可编辑状态
                JScrollPane jsp=new JScrollPane(jta);    //将文本域放入滚动窗口
                jps_2.add(jsp);    //将JScrollPane添加到JPanel容器中

                //添加复选框监听事件
                chkbox1.addItemListener(new ItemListener() {
                    @Override
                    public void itemStateChanged(ItemEvent e) {
                        if(chkbox1.isSelected()){
                            stdout.println("插件mhszed SQL启动");
                            switchs = 1;
                        }else {
                            stdout.println("插件mhszed SQL关闭");
                            switchs = 0;
                        }

                    }
                });
                chkbox2.addItemListener(new ItemListener() {
                    @Override
                    public void itemStateChanged(ItemEvent e) {
                        if (chkbox2.isSelected()){
                            stdout.println("启动 监控Repeater");
                            clicks_Repeater = 64;
                        }else {
                            stdout.println("关闭 监控Repeater");
                            clicks_Repeater = 0;
                        }
                    }
                });
                chkbox3.addItemListener(new ItemListener() {
                    @Override
                    public void itemStateChanged(ItemEvent e) {
                        if(chkbox3.isSelected()) {
                            stdout.println("启动 监控Proxy");
                            clicks_Proxy = 4;
                        }else {
                            stdout.println("关闭 监控Proxy");
                            clicks_Proxy = 0;
                        }
                    }
                });
                chkbox4.addItemListener(new ItemListener() {
                    @Override
                    public void itemStateChanged(ItemEvent e) {
                        if(chkbox4.isSelected()) {
                            stdout.println("启动 值是数字则进行-1、-0");
                            is_int = 1;
                        }else {
                            stdout.println("关闭 值是数字则进行-1、-0");
                            is_int = 0;
                        }
                    }
                });

                chkbox5.addItemListener(new ItemListener() {
                    @Override
                    public void itemStateChanged(ItemEvent e) {
                        if(chkbox5.isSelected()) {
                            stdout.println("启动 自定义payload");
                            jta.setEditable(true);
                            jta.setBackground(Color.WHITE);    //设置背景色
                            JTextArea_int = 1;

                            if (diy_payload_1 == 1){
                                String temp_data = jta.getText();
                                temp_data = temp_data.replaceAll(" ","%20");
                                JTextArea_data_1 = temp_data;
                            }else {
                                JTextArea_data_1 = jta.getText();
                            }

                        }else {
                            stdout.println("关闭 自定义payload");
                            jta.setEditable(false);
                            jta.setBackground(Color.LIGHT_GRAY);    //设置背景色
                            JTextArea_int = 0;
                        }
                    }
                });

                chkbox6.addItemListener(new ItemListener() {
                    @Override
                    public void itemStateChanged(ItemEvent e) {
                        if(chkbox6.isSelected()) {
                            stdout.println("启动 空格url编码");
                            diy_payload_1 = 1;

                            //空格url编码
                            String temp_data = jta.getText();
                            temp_data = temp_data.replaceAll(" ","%20");
                            JTextArea_data_1 = temp_data;
                        }else {
                            stdout.println("关闭 空格url编码");
                            diy_payload_1 = 0;

                            JTextArea_data_1 = jta.getText();
                        }
                    }
                });

                chkbox7.addItemListener(new ItemListener() {
                    @Override
                    public void itemStateChanged(ItemEvent e) {
                        if(chkbox7.isSelected()) {
                            stdout.println("启动 自定义payload参数值置空");
                            diy_payload_2 = 1;
                        }else {
                            stdout.println("关闭 自定义payload参数值置空");
                            diy_payload_2 = 0;
                        }
                    }
                });

                chkbox8.addItemListener(new ItemListener() {
                    @Override
                    public void itemStateChanged(ItemEvent e) {
                        if(chkbox8.isSelected()) {
                            stdout.println("启动 测试Cookie");
                            is_cookie = 2;
                        }else {
                            stdout.println("关闭 测试Cookie");
                            is_cookie = -1;
                        }
                    }
                });

                chkbox9.addItemListener(new ItemListener() {
                    @Override
                    public void itemStateChanged(ItemEvent e) {
                        if(chkbox9.isSelected()) {
                            stdout.println("启动 测试Referer");
                            is_referer = 2;
                        }else {
                            stdout.println("关闭 测试Referer");
                            is_referer = -1;
                        }
                    }
                });

                btn1.addActionListener(new ActionListener() {//清空列表
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        log.clear();//清除log的内容
                        log2.clear();//清除log2的内容
                        log3.clear();//清除log3的内容
                        log4_md5.clear();//清除log4的内容
                        conut = 0;
                        fireTableRowsInserted(log.size(), log.size());//刷新列表中的展示
                        model.fireTableRowsInserted(log3.size(), log3.size());//刷新列表中的展示
                    }
                });

                btn2.addActionListener(new ActionListener() {//加载自定义payload
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        if (diy_payload_1 == 1){
                            String temp_data = jta.getText();
                            temp_data = temp_data.replaceAll(" ","%20");
                            JTextArea_data_1 = temp_data;
                        }else {
                            JTextArea_data_1 = jta.getText();
                        }
                        //写入ini配置文件
                        try {
                            BufferedWriter out = new BufferedWriter(new FileWriter("xia_SQL_diy_payload.ini"));
                            out.write(JTextArea_data_1);
                            out.close();
                        } catch (IOException exception) {
                        }
                    }
                });
                btn3.addActionListener(new ActionListener() {//加载自定义payload
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        if(btn3.getText().equals("启动白名单")){
                            btn3.setText("关闭白名单");
                            white_URL = textField.getText();
                            white_switchs = 1;
                            textField.setEditable(false);
                            textField.setForeground(Color.GRAY);//设置组件的背景色
                        }else {
                            btn3.setText("启动白名单");
                            white_switchs = 0;
                            textField.setEditable(true);
                            textField.setForeground(Color.BLACK);
                        }
                    }
                });

                jps.add(infoPanel);
                jps.add(Box.createVerticalStrut(4));
                jps.add(switchPanel);
                jps.add(Box.createVerticalStrut(4));
                jps.add(whitePanel);
                jps.add(Box.createVerticalStrut(4));
                jps.add(payloadPanel);
                jps.add(Box.createVerticalStrut(4));
                jps.add(actionPanel);






                // tabs with request/response viewers
                JTabbedPane tabs = new JTabbedPane();
                requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                tabs.addTab("Request", requestViewer.getComponent());
                tabs.addTab("Response", responseViewer.getComponent());

                //jp.add(tabs);

                //右边
                splitPanes_2.setLeftComponent(jps);//上面
                splitPanes_2.setRightComponent(jps_2);//下面

                //左边
                splitPanes.setLeftComponent(jp);//上面
                splitPanes.setRightComponent(tabs);//下面

                //整体分布
                splitPane.setLeftComponent(splitPanes);//添加在左面
                splitPane.setRightComponent(splitPanes_2);//添加在右面
                splitPane.setDividerLocation(1000);//设置分割的大小

                // customize our UI components
                callbacks.customizeUiComponent(splitPane);
                callbacks.customizeUiComponent(logTable);
                callbacks.customizeUiComponent(scrollPane);
                callbacks.customizeUiComponent(pane);
                callbacks.customizeUiComponent(jps);
                callbacks.customizeUiComponent(jp);
                callbacks.customizeUiComponent(tabs);

                // add the custom tab to Burp's UI
                callbacks.addSuiteTab(BurpExtender.this);

                // register ourselves as an HTTP listener
                callbacks.registerHttpListener(BurpExtender.this);
                callbacks.registerScannerCheck(BurpExtender.this);
                callbacks.registerContextMenuFactory(BurpExtender.this);

            }
        });
    }
    //
    // implement ITab
    //

    @Override
    public String getTabCaption()
    {
        return "xia SQL";
    }

    @Override
    public Component getUiComponent()
    {
        return splitPane;
    }

    //
    // implement IHttpListener
    //




    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo)
    {

        if(switchs == 1){//插件开关
            if(toolFlag == clicks_Repeater || toolFlag == clicks_Proxy){//监听Repeater
                // only process responses
                if (!messageIsRequest)
                {
                    // create a new log entry with the message details
                    synchronized(log)
                    {
                        //BurpExtender.this.checkVul(messageInfo,toolFlag);
                        Thread thread = new Thread(new Runnable() {
                            public void run() {
                                try {
                                    BurpExtender.this.checkVul(messageInfo,toolFlag);
                                } catch (Exception ex) {
                                    ex.printStackTrace();
                                    BurpExtender.this.stdout.println(ex);
                                }
                            }
                        });
                        thread.start();
                    }
                }
            }

        }

    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        return null;
    }

    @Override
    public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
        //右键发送按钮功能

        List<JMenuItem> listMenuItems = new ArrayList<JMenuItem>(1);
        if(invocation.getToolFlag() == IBurpExtenderCallbacks.TOOL_REPEATER || invocation.getToolFlag() == IBurpExtenderCallbacks.TOOL_PROXY){
            //父级菜单
            IHttpRequestResponse[] responses = invocation.getSelectedMessages();
            JMenuItem jMenu = new JMenuItem("Send to xia SQL");

            jMenu.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    if(switchs == 1) {
                        //不应在Swing事件调度线程中发出HTTP请求，所以需要创建一个Runnable并在 run() 方法中完成工作，后调用 new Thread(runnable).start() 来启动线程
                        Thread thread = new Thread(new Runnable() {
                            public void run() {
                                try {
                                    BurpExtender.this.checkVul(responses[0], 1024);
                                } catch (Exception ex) {
                                    ex.printStackTrace();
                                    BurpExtender.this.stdout.println(ex);
                                }
                            }
                        });
                        thread.start();
                    }else {
                        BurpExtender.this.stdout.println("插件xia SQL关闭状态！");
                    }

                }
            });

            listMenuItems.add(jMenu);


                                       }
            //BurpExtender.this.checkVul(responses,4);
        return listMenuItems;
    }

    private void checkVul(IHttpRequestResponse baseRequestResponse, int toolFlag){

            int is_add; //用于判断是否要添加扫描
            String change_sign_1 = ""; //用于显示第一个列表框的状态 变化 部分的内容

            //把当前url和参数进行md5加密，用于判断该url是否已经扫描过
            List<IParameter>paraLists= helpers.analyzeRequest(baseRequestResponse).getParameters();
            //提取 Referer 头的值（只在开启 测试Referer 时），Referer 不属于 IParameter，需要单独处理
            String referer_value = is_referer == 2 ? getRefererValue(baseRequestResponse.getRequest()) : null;
            if (is_referer == 2 && referer_value == null){
                stdout.println("请求头中无 Referer，跳过 Referer 测试");
            }
            temp_data = String.valueOf(helpers.analyzeRequest(baseRequestResponse).getUrl());//url
            //stdout.println(temp_data);
            String[] temp_data_strarray=temp_data.split("\\?");
            String temp_data =(String) temp_data_strarray[0];//获取问号前面的字符串

            //检测白名单
            String[] white_URL_list = white_URL.split(",");
            int white_swith = 0;
            if(white_switchs == 1){
                white_swith = 0;
                for(int i=0;i<white_URL_list.length;i++){
                    if(temp_data.contains(white_URL_list[i])){
                        this.stdout.println("白名单URL！"+temp_data);
                        white_swith = 1;
                    }
                }
                if(white_swith == 0) {
                    this.stdout.println("不是白名单URL！"+temp_data);
                    return;
                }
            }

            //用于判断页面后缀是否为静态文件
            if(toolFlag == 4 || toolFlag ==64){//流量是Repeater与proxy来的就对其后缀判断
                String[] static_file = {"jpg","png","gif","css","js","pdf","mp3","mp4","avi"};
                String[] static_file_1 =temp_data.split("\\.");
                String static_file_2 = static_file_1[static_file_1.length-1];//获取最后一个.内容
                //this.stdout.println(static_file_2);
                for(String i:static_file){
                    if(static_file_2.equals(i)){
                        this.stdout.println("当前url为静态文件："+temp_data+"\n");
                        return;
                    }
                }
            }

        //stdout.println(temp_data);

            String request_data = null;
            String[] request_datas;
            is_add = 0;
            for (IParameter para : paraLists){// 循环获取参数，判断类型，再构造新的参数，合并到新的请求包中。
                if (para.getType() == 0 || para.getType() == 1 || para.getType() == 6 || para.getType() == is_cookie) { //getTpe()就是来判断参数是在那个位置的
                    if(is_add == 0){
                        is_add = 1;
                    }
                    temp_data += "+"+para.getName();

                    //判断是否为json嵌套 考虑性能消耗，判断json嵌套 和 json中带列表的  才用正则处理
                    if(para.getType() == 6 && request_data == null){
                        try {
                            //stdout.println(helpers.bytesToString(baseRequestResponse.getRequest()));//查看数据包内容
                            request_data = helpers.bytesToString(baseRequestResponse.getRequest()).split("\r\n\r\n")[1];
                            //stdout.println(request_data);

                            //json嵌套
                            request_datas = request_data.split("\\{");
                            if(request_datas.length >2){
                                is_add = 2;
                            }
                            //json中有列表
                            request_datas = request_data.split("\":\\[");
                            if(request_datas.length >1){
                                is_add = 2;
                            }
                        } catch (Exception e) {
                            stdout.println(e);
                        }
                    }
                }
            }



            //url+参数进行编码
            temp_data += "+"+helpers.analyzeRequest(baseRequestResponse).getMethod();
            //Referer 测试开启时计入指纹，这样开关状态不同会各自扫描一次，且已扫描过的组合不会重复扫
            if (is_referer == 2 && referer_value != null){
                temp_data += "+referer";
                if (is_add == 0){
                    is_add = 1; //无其它可测参数时，仅测 Referer 也要进入扫描
                }
            }
            //this.stdout.println(temp_data);
            this.stdout.println("\nMD5(\""+temp_data+"\")");
            temp_data = MD5(temp_data);
            this.stdout.println(temp_data);



            for (Request_md5 i : log4_md5){
                if(i.md5_data.equals(temp_data)){//判断md5值是否一样，且右键发送过来的请求不进行md5验证
                    if(toolFlag == 1024){
                        temp_data = String.valueOf(System.currentTimeMillis());
                        this.stdout.println(temp_data);
                        temp_data = MD5(temp_data);
                        this.stdout.println(temp_data);
                    }else {
                        return;
                    }


                }
            }

            //用于判断是否要处理这个请求
            if (is_add != 0){
                log4_md5.add(new Request_md5(temp_data));//保存对应对md5
                stdout.println(is_add);
                stdout.println(request_data);

                int row = log.size();
                try{
                    original_data_len = callbacks.saveBuffersToTempFiles(baseRequestResponse).getResponse().length;//更新原始数据包的长度
                    stdout.println(original_data_len);
                    if(original_data_len <= 0){
                        stdout.println("该数据包无响应");
                        return;
                    }
                } catch (Exception ex) {
                    stdout.println("该数据包无响应");
                    return;
                }

                log.add(new LogEntry(conut,toolFlag, callbacks.saveBuffersToTempFiles(baseRequestResponse),helpers.analyzeRequest(baseRequestResponse).getUrl(),"","","",temp_data,0,"run……",999));
                conut += 1;
                fireTableRowsInserted(row, row);
            }

            QuoteParityEvaluator.ResponseProfile baselineProfile = buildResponseProfile(baseRequestResponse.getResponse());
            if (baselineProfile == null) {
                stdout.println("该数据包响应无法用于引号奇偶性判断");
            }

            //处理参数
            List<IParameter>paraList= helpers.analyzeRequest(baseRequestResponse).getParameters();
            byte[] new_Request = baseRequestResponse.getRequest();
            int json_count = -1;//记录json嵌套次数

            //****************************************
            // 循环获取参数
            //****************************************
            String para_name = "";//用来记录上一次循环的参数名
            for (IParameter para : paraList){// 循环获取参数
                int switch_para = 0;//用来判断该参数是否要处理 0 要处理 1 跳过

                if(para.getType() == 6){
                    json_count += 1;
                }

                //payload：四次引号用于严格的奇偶性对照
                ArrayList<String> payloads = new ArrayList<>();
                payloads.add("'");
                payloads.add("''");
                payloads.add("'''");
                payloads.add("''''");



                if (para.getType() == 0 || para.getType() == 1 || para.getType() == 6 || para.getType() == is_cookie){ //getTpe()就是来判断参数是在那个位置的
                    String key = para.getName();//获取参数的名称
                    String value = para.getValue();//获取参数的值
                    if (isGarbledParameter(key, value)) {
                        continue;
                    }
                    String originalValue = value;
                    QuoteParityEvaluator.ResponseProfile[] quoteProfiles = new QuoteParityEvaluator.ResponseProfile[4];
                    int[] quoteLogRows = new int[4];
                    for (int quoteIndex = 0; quoteIndex < quoteLogRows.length; quoteIndex++) {
                        quoteLogRows[quoteIndex] = -1;
                    }
                    stdout.println("\n\n原始数据："+key+":"+value);//输出原始的键值数据

                    if(is_int == 1){//开关，用于判断是否要开启-1、-0的操作
                        if (value.matches("[0-9]+")) {//用于判读参数的值是否为纯数字
                            payloads.add("-1");
                            payloads.add("-0");
                        }
                    }

                    //自定义payload
                    if(JTextArea_int == 1){
                        String[] JTextArea_data = JTextArea_data_1.split("\n");
                        for(String a:JTextArea_data){
                            //stdout.println(a);
                            //stdout.println("------");
                            payloads.add(a);
                        }
                    }

                    int change = 0; //数字 payload 的长度对照基准
                    QuoteParityEvaluator.ResponseProfile numericProfile0 = null;
                    int numericLogRowRef = -1;

                    //****************************************
                    // 循环payload
                    //****************************************
                    for (int payloadIndex = 0; payloadIndex < payloads.size(); payloadIndex++) {
                        String payload = payloads.get(payloadIndex);
                        long time_1 = 0,time_2 = 0;
                        int quoteCount = payloadIndex < 4 ? payloadIndex + 1 : 0;
                        String payloadBaseValue = originalValue;

                        if(JTextArea_int == 1){
                            //自定义payload //参数值为空
                            if(diy_payload_2 == 1 && quoteCount == 0 && !"-1".equals(payload) && !"-0".equals(payload)){
                                payloadBaseValue = "";
                            }
                        }

                        //stdout.println(key+":"+value+payload);//输出添加payload的键和值
                        IHttpService iHttpService = baseRequestResponse.getHttpService();

                        //新的请求包
                        IHttpRequestResponse requestResponse = null; //用于过if内的变量
                        
                        if(para.getType() == 6){
                            List<String> headers = helpers.analyzeRequest(baseRequestResponse).getHeaders();
                            if(is_add ==1) {
                                //json格式
                                stdout.println("json");
                                String newBody = "{"; //json body的内容

                                for (IParameter paras : paraList) {//循环所有参数，用来自定义json格式body做准备
                                    if (paras.getType() == 6) {//只要json格式的数据
                                        if (key.equals(paras.getName()) && originalValue.equals(paras.getValue())) {//判断现在的键和值是否是需要添加payload的键和值
                                            newBody += "\"" + paras.getName() + "\":" + "\"" + paras.getValue() + payload + "\",";//构造json的body
                                        } else {
                                            newBody += "\"" + paras.getName() + "\":" + "\"" + paras.getValue() + "\",";//构造json的body
                                        }
                                    }
                                }

                                newBody = newBody.substring(0, newBody.length() - 1); //去除最后一个,
                                newBody += "}";//json body的内容

                                byte[] bodyByte = newBody.getBytes();
                                byte[] new_Requests = helpers.buildHttpMessage(headers, bodyByte); //关键方法

                                time_1 = System.currentTimeMillis();
                                requestResponse = callbacks.makeHttpRequest(iHttpService, new_Requests);//发送请求
                                time_2 = System.currentTimeMillis();
                            }else if (is_add ==2){
                                //json嵌套
                                //stdout.println("json嵌套");

                                request_data = request_data.replaceAll("\r","");//burp2.x json自动格式美化处理
                                request_data = request_data.replaceAll("\n","");//burp2.x json自动格式美化处理

                                String[] request_data_temp = request_data.split(",\"");//用于临时保存切割的post体内容
                                String request_data_body = "";//连接字符串
                                String request_data_body_temp = "";//修改后的body和需要临时编辑的字符串


                                for(int i=0;i < request_data_temp.length;i++){
                                    if(i==json_count){//判断现在修改的参数
                                        request_data_body_temp = request_data_temp[i];

                                        stdout.println("准备修改的值："+request_data_body_temp);
                                        while (true){
                                            //空列表如："test":[]跳过处理
                                            if(request_data_body_temp.contains(":[]")) {
                                                stdout.println(request_data_body_temp+"跳过");
                                                request_data_body += "\""+request_data_temp[i]+",";//把跳过的字符串连接上
                                                json_count += 1;
                                                i += 1;
                                                request_data_body_temp = request_data_temp[i];
                                            }else {
                                                break;
                                            }
                                        }


                                        //null、true、false等跳过处理
                                        if(request_data_body_temp.toLowerCase().contains(":null") || request_data_body_temp.toLowerCase().contains(":true") || request_data_body_temp.toLowerCase().contains(":false")) {
                                            stdout.println(request_data_body_temp+"跳过");
                                            switch_para = 1;
                                            break;
                                        }


                                        if(request_data_body_temp.contains("\":")){

                                            if(para.getName().equals(para_name)){
                                                //处理json嵌套列表，这种情况只跑一次
                                                stdout.println("json嵌套列表，这个参数处理过了，跳过");
                                                json_count -= 1;
                                                switch_para = 1;
                                                break;
                                            }

                                            //判断字符串中是否有":，如果有则为正常json内容
                                            Pattern p = Pattern.compile(".*:\\s?\\[?\\s?(.*?$)");
                                            Matcher m = p.matcher(request_data_body_temp);
                                            if(m.find()){
                                                request_data_body_temp = m.group(1);//获取:后面的内容
                                            }
                                            if(request_data_body_temp.contains("\"")){//判断内容是否为字符串
                                                request_data_body_temp = request_data_temp[i];
                                                //修改内容，添加payload
                                                request_data_body_temp = request_data_body_temp.replaceAll("^(.*:.*?\")(.*?)(\"[^\"]*)$","$1$2"+payload+"$3");
                                                stdout.println(request_data_body_temp);
                                                request_data_body+= "\""+request_data_body_temp +",";
                                            }else {
                                                request_data_body_temp = request_data_temp[i];
                                                //修改内容，添加payload  纯数字
                                                request_data_body_temp = request_data_body_temp.replaceAll("^(.*:.*?)(\\d*)([^\"\\d]*)$","$1\"$2"+payload+"\"$3");
                                                stdout.println(request_data_body_temp);
                                                request_data_body+= "\""+request_data_body_temp +",";
                                            }

                                        }else {
                                            stdout.println("处理过，无需处理");
                                            switch_para = 1;
                                            if(para.getName().equals(para_name)){
                                                //处理json嵌套列表，这种情况只跑一次
                                                stdout.println("json嵌套列表，已经处理过第一个值");
                                            }
                                            break;

                                            /*
                                            //字符串中没有":，表示json格式中嵌套的列表

                                            if(request_data_body_temp.contains("\"")) {//判断内容是否为字符串
                                                //修改内容，添加payload
                                                request_data_body_temp = request_data_body_temp.replaceAll("^(\")(.*?)(\".*?)$","$1$2"+payload+"$3");
                                                request_data_body+= "\""+request_data_body_temp +",";
                                            }else {
                                                //不是字符串，则为纯数字
                                                request_data_body_temp = request_data_body_temp.replaceAll("^(\\d*)(.*?)$","\"$1"+payload+"\"$2");
                                                request_data_body+= "\""+request_data_body_temp +",";
                                            }
                                            */
                                        }
                                        //stdout.println(request_data_body_temp);


                                    }else {
                                        request_data_body += "\""+request_data_temp[i]+",";
                                    }
                                }

                                if(switch_para == 1){
                                    //跳过这个参数
                                    break;
                                }
                                if(para.getName().equals(para_name)){
                                    //处理json嵌套列表，这种情况只跑一次
                                    stdout.println("json嵌套列表，已经处理过第一个值!!!!");
                                }


                                request_data_body = request_data_body.substring(0, request_data_body.length() - 1); //去除最后一个,
                                request_data_body = request_data_body.substring(1,request_data_body.length()); //去除第一个"

                                byte[] bodyByte = request_data_body.getBytes();
                                byte[] new_Requests = helpers.buildHttpMessage(headers, bodyByte); //关键方法
                                time_1 = System.currentTimeMillis();
                                requestResponse = callbacks.makeHttpRequest(iHttpService, new_Requests);//发送请求
                                time_2 = System.currentTimeMillis();

                            }
                        }else {
                            stdout.println("普通格式");
                            //不是json格式
                            IParameter newPara = helpers.buildParameter(key,payloadBaseValue + payload, para.getType()); //构造新的参数
                            byte[] newRequest = helpers.updateParameter(new_Request, newPara);//更新请求包的参数

                            time_1 = System.currentTimeMillis();
                            requestResponse = callbacks.makeHttpRequest(iHttpService, newRequest);//发送请求
                            time_2 = System.currentTimeMillis();

                        }

                        if (requestResponse == null || requestResponse.getResponse() == null) {
                            stdout.println("payload 请求无响应，跳过引号奇偶性判断：" + payload);
                            continue;
                        }

                        //判断数据长度是否会变化
                        String change_sign = "";//第二个表格中 变化 的内容
                        QuoteParityEvaluator.ResponseProfile responseProfile = buildResponseProfile(requestResponse.getResponse());

                        // ── 新 Evaluator 描述 ──
                        if (quoteCount >= 1 && quoteCount <= 4) {
                            if (is_add != 2 && responseProfile != null) {
                                quoteProfiles[quoteCount - 1] = responseProfile;
                                change_sign = describeQuoteProbe(quoteCount, baselineProfile, responseProfile);
                            } else if (is_add == 2) {
                                change_sign = "嵌套 JSON 不参与引号奇偶性判断";
                            }
                        } else if ("-1".equals(payload)) {
                            change = requestResponse.getResponse().length;
                        } else if ("-0".equals(payload)) {
                            if (change != requestResponse.getResponse().length && responseProfile != null) {
                                numericProfile0 = responseProfile;
                            }
                        } else {
                            if(time_2-time_1 >= 3000){
                                change_sign = "time > 3";
                            }else {
                                change_sign = "diy payload";
                            }
                        }

                        // ── 原始简单长度对比检测（恢复原版，与新版并行）──
                        if("-1".equals(payload)){
                            // -1 作为数字型长度基准
                            change = requestResponse.getResponse().length;
                        } else if("-0".equals(payload)){
                            // -0 与 -1 对比，不一致说明可能存在数字型注入
                            if(change != requestResponse.getResponse().length){
                                if(requestResponse.getResponse().length == original_data_len){
                                    change_sign = (change_sign.isEmpty() ? "" : change_sign + "；") + "✔ ==> ?";
                                }else{
                                    change_sign = (change_sign.isEmpty() ? "" : change_sign + "；") + "✔ "+ (change-requestResponse.getResponse().length);
                                }
                                if (!change_sign_1.contains("⚠") && !change_sign_1.contains("误报")) change_sign_1 = " ✔";
                            }
                        } else if("'".equals(payload)){
                            // 第一个单引号 保存长度基准
                            if(change == 0){
                                change = requestResponse.getResponse().length;
                            }
                        } else if("''".equals(payload)){
                            // 两个单引号 对比
                            if(change != requestResponse.getResponse().length){
                                if(requestResponse.getResponse().length == original_data_len){
                                    change_sign = (change_sign.isEmpty() ? "" : change_sign + "；") + "✔ ==> ?";
                                }else{
                                    change_sign = (change_sign.isEmpty() ? "" : change_sign + "；") + "✔ "+ (change-requestResponse.getResponse().length);
                                }
                                if (!change_sign_1.contains("⚠") && !change_sign_1.contains("误报")) change_sign_1 = " ✔";
                            }
                        } else if(!payload.startsWith("'") && time_2-time_1 >= 3000){
                            // 自定义payload 延时检测
                            if (!change_sign_1.contains("⚠") && !change_sign_1.contains("误报")) change_sign_1 = " ✔";
                        }

                        //把响应内容保存在log2中
                        int logRow = log2.size();
                        log2.add(new LogEntry(conut,toolFlag, callbacks.saveBuffersToTempFiles(requestResponse),helpers.analyzeRequest(requestResponse).getUrl(),key,payloadBaseValue+payload,change_sign,temp_data,time_2-time_1,"end",helpers.analyzeResponse(requestResponse.getResponse()).getStatusCode()));
                        if (quoteCount >= 1 && quoteCount <= 4 && is_add != 2 && responseProfile != null) {
                            quoteLogRows[quoteCount - 1] = logRow;
                        }
                        if ("-0".equals(payload)) {
                            numericLogRowRef = logRow;
                        }

                    }

                    QuoteParityEvaluator.Result quoteParityResult = baselineProfile == null
                            ? QuoteParityEvaluator.Result.inconclusive("原始响应无法作为基线")
                            : QuoteParityEvaluator.evaluate(baselineProfile, quoteProfiles);
                    if (quoteParityResult.suspicious) {
                        change_sign_1 = " ✔⚠";
                        if (quoteLogRows[3] >= 0) {
                            LogEntry lastQuoteLog = log2.get(quoteLogRows[3]);
                            lastQuoteLog.setChange(lastQuoteLog.change + "；" + quoteParityResult.message);
                        }
                    }

                    // ORDER BY 探针已禁用（原版无此功能，每条参数额外发4个请求导致卡顿）
                    // 如需启用，取消下方注释：
                    // if (para.getType() != 6 && isOrderByCandidateParameter(key)) {
                    //     OrderByEvaluator.Result orderResult = runOrderByProbes(baseRequestResponse, new_Request, para, key, baselineProfile, toolFlag, temp_data);
                    //     if (orderResult.suspicious) {
                    //         change_sign_1 = " ✔⚠";
                    //     }
                    // }

                    // single quote probe introduced DB error -> strong signal, mark left red
                    if (baselineProfile != null && !baselineProfile.hasDatabaseError) {
                        for (QuoteParityEvaluator.ResponseProfile qp : quoteProfiles) {
                            if (qp != null && qp.hasDatabaseError) {
                                change_sign_1 = " ✔⚠";
                                break;
                            }
                        }
                    }
                    // 类型转换报错(如 java.lang.Integer)且无真实DB报错 => 大概率误报，左表标注(不覆盖强信号)
                    if (baselineProfile != null && !change_sign_1.contains("⚠")) {
                        for (QuoteParityEvaluator.ResponseProfile qp : quoteProfiles) {
                            if (qp != null && qp.hasOnlyTypeConversionNotRealDbError()) {
                                change_sign_1 = " ✗误报";
                                break;
                            }
                        }
                    }
                    if (numericProfile0 != null && baselineProfile != null
                            && numericProfile0.hasRealDatabaseErrorNotTypeConversion()
                            && !baselineProfile.hasDatabaseError
                            && numericLogRowRef >= 0) {
                        change_sign_1 = " ✔⚠";
                        log2.get(numericLogRowRef).setChange("数字型异常：出现关键词[" + numericProfile0.databaseErrorMarker + "]→大概率是SQL注入");
                    }
                }
                para_name = para.getName();//用于判断json嵌套里面有列表，列表中带值只跑一次
                stdout.println(json_count);

            }

            //****************************************
            // Referer 头注入（开启 测试Referer 时）
            //****************************************
            if (is_referer == 2 && referer_value != null && !isGarbledParameter("Referer", referer_value)) {
                stdout.println("\n\n原始数据：Referer:"+referer_value);//输出原始的键值数据

                //payload：四次引号用于严格的奇偶性对照（Referer 值是URL，不会是纯数字，无需 -1、-0）
                ArrayList<String> refererPayloads = new ArrayList<>();
                refererPayloads.add("'");
                refererPayloads.add("''");
                refererPayloads.add("'''");
                refererPayloads.add("''''");

                //自定义payload
                if(JTextArea_int == 1){
                    String[] JTextArea_data = JTextArea_data_1.split("\n");
                    for(String a:JTextArea_data){
                        refererPayloads.add(a);
                    }
                }

                QuoteParityEvaluator.ResponseProfile[] quoteProfiles = new QuoteParityEvaluator.ResponseProfile[4];
                int[] quoteLogRows = new int[4];
                for (int quoteIndex = 0; quoteIndex < quoteLogRows.length; quoteIndex++) {
                    quoteLogRows[quoteIndex] = -1;
                }

                IHttpService iHttpService = baseRequestResponse.getHttpService();
                int change_quote = 0; // ' 与 '' 的长度对照基准

                for (int payloadIndex = 0; payloadIndex < refererPayloads.size(); payloadIndex++) {
                    String payload = refererPayloads.get(payloadIndex);
                    long time_1 = 0,time_2 = 0;
                    int quoteCount = payloadIndex < 4 ? payloadIndex + 1 : 0;

                    //含换行的payload会破坏HTTP头结构，跳过，防止发出畸形请求
                    if (payload.contains("\r") || payload.contains("\n")) {
                        stdout.println("Referer payload 含换行符，跳过："+payload);
                        continue;
                    }

                    byte[] newRequest = buildRefererRequest(baseRequestResponse.getRequest(), referer_value + payload);
                    if (newRequest == null) {
                        stdout.println("Referer 请求构造失败，跳过");
                        break;
                    }
                    time_1 = System.currentTimeMillis();
                    IHttpRequestResponse requestResponse = callbacks.makeHttpRequest(iHttpService, newRequest);//发送请求
                    time_2 = System.currentTimeMillis();

                    if (requestResponse == null || requestResponse.getResponse() == null) {
                        stdout.println("payload 请求无响应，跳过引号奇偶性判断：" + payload);
                        continue;
                    }

                    String change_sign = "";//"变化"列的内容
                    QuoteParityEvaluator.ResponseProfile responseProfile = buildResponseProfile(requestResponse.getResponse());

                    // ── Evaluator 描述 ──
                    if (quoteCount >= 1 && quoteCount <= 4) {
                        if (responseProfile != null) {
                            quoteProfiles[quoteCount - 1] = responseProfile;
                            change_sign = describeQuoteProbe(quoteCount, baselineProfile, responseProfile);
                        }
                    } else {
                        if(time_2-time_1 >= 3000){
                            change_sign = "time > 3";
                        }else {
                            change_sign = "diy payload";
                        }
                    }

                    // ── 原始简单长度对比检测（' 与 '' 对照，与参数检测保持一致）──
                    if("'".equals(payload)){
                        // 第一个单引号 保存长度基准
                        if(change_quote == 0){
                            change_quote = requestResponse.getResponse().length;
                        }
                    } else if("''".equals(payload)){
                        // 两个单引号 对比
                        if(change_quote != 0 && change_quote != requestResponse.getResponse().length){
                            if(requestResponse.getResponse().length == original_data_len){
                                change_sign = (change_sign.isEmpty() ? "" : change_sign + "；") + "✔ ==> ?";
                            }else{
                                change_sign = (change_sign.isEmpty() ? "" : change_sign + "；") + "✔ "+ (change_quote-requestResponse.getResponse().length);
                            }
                            if (!change_sign_1.contains("⚠") && !change_sign_1.contains("误报")) change_sign_1 = " ✔";
                        }
                    } else if(!payload.startsWith("'") && time_2-time_1 >= 3000){
                        // 自定义payload 延时检测
                        if (!change_sign_1.contains("⚠") && !change_sign_1.contains("误报")) change_sign_1 = " ✔";
                    }

                    //把响应内容保存在log2中
                    int logRow = log2.size();
                    log2.add(new LogEntry(conut,toolFlag, callbacks.saveBuffersToTempFiles(requestResponse),helpers.analyzeRequest(requestResponse).getUrl(),"Referer",referer_value+payload,change_sign,temp_data,time_2-time_1,"end",helpers.analyzeResponse(requestResponse.getResponse()).getStatusCode()));
                    if (quoteCount >= 1 && quoteCount <= 4 && responseProfile != null) {
                        quoteLogRows[quoteCount - 1] = logRow;
                    }
                }

                QuoteParityEvaluator.Result quoteParityResult = baselineProfile == null
                        ? QuoteParityEvaluator.Result.inconclusive("原始响应无法作为基线")
                        : QuoteParityEvaluator.evaluate(baselineProfile, quoteProfiles);
                if (quoteParityResult.suspicious) {
                    change_sign_1 = " ✔⚠";
                    if (quoteLogRows[3] >= 0) {
                        LogEntry lastQuoteLog = log2.get(quoteLogRows[3]);
                        lastQuoteLog.setChange(lastQuoteLog.change + "；" + quoteParityResult.message);
                    }
                }

                // single quote probe introduced DB error -> strong signal, mark left red
                if (baselineProfile != null && !baselineProfile.hasDatabaseError) {
                    for (QuoteParityEvaluator.ResponseProfile qp : quoteProfiles) {
                        if (qp != null && qp.hasDatabaseError) {
                            change_sign_1 = " ✔⚠";
                            break;
                        }
                    }
                }
                // 类型转换报错且无真实DB报错 => 大概率误报，左表标注(不覆盖强信号)
                if (baselineProfile != null && !change_sign_1.contains("⚠")) {
                    for (QuoteParityEvaluator.ResponseProfile qp : quoteProfiles) {
                        if (qp != null && qp.hasOnlyTypeConversionNotRealDbError()) {
                            change_sign_1 = " ✗误报";
                            break;
                        }
                    }
                }
            }

        //用于更新是否已经跑完所有payload的状态
        int firstUpdated = -1, lastUpdated = -1;
        for(int i = 0; i < log.size(); i++){
            if(temp_data.equals(log.get(i).data_md5)){
                log.get(i).setState("end!"+change_sign_1);
                if (firstUpdated < 0) firstUpdated = i;
                lastUpdated = i;
            }
        }

        //刷新第一个列表框
        //BurpExtender.this.fireTableRowsInserted(log.size(), log.size());
        //只刷新状态变化的行，避免全表重绘卡顿
        if (firstUpdated >= 0) {
            BurpExtender.this.fireTableRowsUpdated(firstUpdated, lastUpdated);
        }
        //第一个表格 继续选中之前选中的值
        BurpExtender.this.logTable.setRowSelectionInterval(BurpExtender.this.select_row,BurpExtender.this.select_row);



    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (existingIssue.getIssueName().equals(newIssue.getIssueName()))
            return -1;
        else return 0;
    }
    //
    // extend AbstractTableModel
    //

    @Override
    public int getRowCount()
    {
        return log.size();

    }

    @Override
    public int getColumnCount()
    {
        return 5;
    }

    @Override
    public String getColumnName(int columnIndex)
    {
        switch (columnIndex)
        {
            case 0:
                return "#";
            case 1:
                return "来源";
            case 2:
                return "URL";
            case 3:
                return "返回包长度";
            case 4:
                return "状态";
            default:
                return "";
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex)
    {
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex)
    {
        LogEntry logEntry = log.get(rowIndex);

        switch (columnIndex)
        {
            case 0:
                return logEntry.id;
            case 1:
                return callbacks.getToolName(logEntry.tool);
            case 2:
                return logEntry.url.toString();
            case 3:
                return logEntry.requestResponse.getResponse().length;//返回响应包的长度
            case 4:
                return logEntry.state;
            default:
                return "";
        }
    }


    //model2
    class MyModel extends AbstractTableModel {

        @Override
        public int getRowCount()
        {
            return log3.size();
        }

        @Override
        public int getColumnCount()
        {
            return 6;
        }

        @Override
        public String getColumnName(int columnIndex)
        {
            switch (columnIndex)
            {
                case 0:
                    return "参数";
                case 1:
                    return "payload";
                case 2:
                    return "返回包长度";
                case 3:
                    return "变化";
                case 4:
                    return "用时";
                case 5:
                    return "响应码";
                default:
                    return "";
            }
        }

        @Override
        public Class<?> getColumnClass(int columnIndex)
        {
            return String.class;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex)
        {
            LogEntry logEntry2 = log3.get(rowIndex);

            switch (columnIndex)
            {
                case 0:
                    return logEntry2.parameter;
                case 1:
                    return logEntry2.value;
                case 2:
                    return logEntry2.requestResponse.getResponse().length;//返回响应包的长度
                case 3:
                    return logEntry2.change;
                case 4:
                    return logEntry2.times;
                case 5:
                    return logEntry2.response_code;
                default:
                    return "";
            }
        }
    }




    //
    // implement IMessageEditorController
    // this allows our request/response viewers to obtain details about the messages being displayed
    //

    @Override
    public byte[] getRequest()
    {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse()
    {
        return currentlyDisplayedItem.getResponse();
    }

    @Override
    public IHttpService getHttpService()
    {
        return currentlyDisplayedItem.getHttpService();
    }

    //
    // extend JTable to handle cell selection
    //

    private class Table extends JTable
    {
        public Table(TableModel tableModel)
        {
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend)
        {
            // show the log entry for the selected row
            LogEntry logEntry = log.get(row);
            data_md5_id = logEntry.data_md5;
            //stdout.println(log_id);//输出目前选中的行数
            select_row = logEntry.id;

            log3.clear();
            for (int i = 0; i < log2.size(); i++) {//筛选出目前选中的原始数据包--》衍生出的带有payload的数据包
                 if(log2.get(i).data_md5.equals(data_md5_id)){
                     log3.add(log2.get(i));
                 }
            }
            //刷新列表界面
            model.fireTableRowsInserted(log3.size(), log3.size());
            model.fireTableDataChanged();

            requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
            responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
            currentlyDisplayedItem = logEntry.requestResponse;

            super.changeSelection(row, col, toggle, extend);
        }
    }

    private class Table_log2 extends JTable
    {
        public Table_log2(TableModel tableModel)
        {
            super(tableModel);
        }

        // 鼠标悬停时显示"变化"列完整内容（替代原 prepareRenderer 自动换行，避免绘制期 setRowHeight 造成卡顿）
        @Override
        public String getToolTipText(java.awt.event.MouseEvent e) {
            int row = rowAtPoint(e.getPoint());
            int col = columnAtPoint(e.getPoint());
            if (row >= 0 && col == 3) {
                Object val = getValueAt(row, col);
                return val == null ? null : val.toString();
            }
            return super.getToolTipText(e);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend)
        {

            // show the log entry for the selected row
            LogEntry logEntry = log3.get(row);
            requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
            responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
            currentlyDisplayedItem = logEntry.requestResponse;

            super.changeSelection(row, col, toggle, extend);
        }
    }

    //存放数据包的md5值，用于匹配该数据包已请求过
    private static class Request_md5
    {
        final String md5_data;

        Request_md5(String md5_data)
        {
            this.md5_data = md5_data;
        }
    }
    //
    // class to hold details of each log entry
    //
    private static class LogEntry
    {
        final int id;
        final int tool;
        final IHttpRequestResponsePersisted requestResponse;
        final URL url;
        final String parameter;
        final String value;
        String change;
        final String data_md5;
        final long times;
        final int response_code;
        String state;


        LogEntry(int id,int tool, IHttpRequestResponsePersisted requestResponse, URL url,String parameter,String value,String change,String data_md5,long times,String state,int response_code)
        {
            this.id = id;
            this.tool = tool;
            this.requestResponse = requestResponse;
            this.url = url;
            this.parameter = parameter;
            this.value = value;
            this.change = change;
            this.data_md5 = data_md5;
            this.times = times;
            this.state = state;
            this.response_code = response_code;
        }

        public String setState(String state){
            this.state = state;
            return this.state;
        }

        public String setChange(String change){
            this.change = change;
            return this.change;
        }
    }

    private OrderByEvaluator.Result runOrderByProbes(IHttpRequestResponse baseRequestResponse, byte[] originalRequest,
                                                      IParameter parameter, String key,
                                                      QuoteParityEvaluator.ResponseProfile baselineProfile,
                                                      int toolFlag, String scanId) {
        if (baselineProfile == null || baselineProfile.hasDatabaseError) {
            stdout.println("原始响应无法用于 ORDER BY 排序探测：" + key);
            return OrderByEvaluator.Result.noFinding();
        }

        String[] replacementValues = {"1,1", "1,0", "1,2", "1,999"};
        QuoteParityEvaluator.ResponseProfile[] profiles = new QuoteParityEvaluator.ResponseProfile[4];
        int[] logRows = {-1, -1, -1, -1};
        IHttpService httpService = baseRequestResponse.getHttpService();

        for (int index = 0; index < replacementValues.length; index++) {
            String replacementValue = replacementValues[index];
            try {
                IParameter replacementParameter = helpers.buildParameter(key, replacementValue, parameter.getType());
                byte[] replacementRequest = helpers.updateParameter(originalRequest, replacementParameter);
                long startedAt = System.currentTimeMillis();
                IHttpRequestResponse requestResponse = callbacks.makeHttpRequest(httpService, replacementRequest);
                long elapsed = System.currentTimeMillis() - startedAt;

                if (requestResponse == null || requestResponse.getResponse() == null) {
                    stdout.println("ORDER BY 探针无响应：" + key + "=" + replacementValue);
                    continue;
                }

                QuoteParityEvaluator.ResponseProfile profile = buildResponseProfile(requestResponse.getResponse());
                if (profile == null) {
                    continue;
                }
                profiles[index] = profile;
                logRows[index] = log2.size();
                log2.add(new LogEntry(conut, toolFlag, callbacks.saveBuffersToTempFiles(requestResponse),
                        helpers.analyzeRequest(requestResponse).getUrl(), key, replacementValue, "",
                        scanId, elapsed, "end", helpers.analyzeResponse(requestResponse.getResponse()).getStatusCode()));
            } catch (Exception exception) {
                stdout.println("ORDER BY 探针请求失败：" + key + "=" + replacementValue + "；" + exception);
            }
        }

        OrderByEvaluator.Result result = OrderByEvaluator.evaluate(baselineProfile, profiles);
        if (!result.suspicious) {
            return result;
        }
        for (int index = 0; index < logRows.length; index++) {
            if (logRows[index] >= 0) {
                LogEntry probeLog = log2.get(logRows[index]);
                probeLog.setChange(describeOrderByProbe(index, baselineProfile, profiles[index]));
            }
        }
        if (logRows[3] >= 0) {
            LogEntry lastProbe = log2.get(logRows[3]);
            lastProbe.setChange(lastProbe.change + "；" + result.message);
        }
        return result;
    }

    private boolean isOrderByCandidateParameter(String key) {
        if (key == null) {
            return false;
        }
        String normalized = key.trim().toLowerCase(Locale.ROOT);
        String[] excludedNames = {"limit", "offset", "page", "page_no", "page_num", "page_size",
                "per_page", "start", "start_row", "cursor", "pagination", "paginate"};
        for (String excludedName : excludedNames) {
            if (normalized.equals(excludedName)) {
                return false;
            }
        }
        String[] candidateNames = {"order", "orderby", "order_by", "order-by", "orderfield", "order_field",
                "ordercolumn", "order_column", "sort", "sortby", "sort_by", "sort-by", "sortfield",
                "sort_field", "sortcolumn", "sort_column"};
        for (String candidateName : candidateNames) {
            if (normalized.equals(candidateName)) {
                return true;
            }
        }
        return false;
    }

    private String describeOrderByProbe(int probeIndex, QuoteParityEvaluator.ResponseProfile baseline,
                                        QuoteParityEvaluator.ResponseProfile probe) {
        boolean expectedNormal = probeIndex == 0 || probeIndex == 2;
        String prefix = expectedNormal ? "ORDER BY 正常探针" : "ORDER BY 异常探针";
        if (probe.hasDatabaseError && !baseline.hasDatabaseError) {
            return prefix + "出现关键词[" + probe.databaseErrorMarker + "]" + "→大概率是SQL注入";
        }
        if (probe.hasOnlyTypeConversionNotRealDbError()) {
            return prefix + "大概率误报：类型转换错误[" + probe.typeConversionMarker + "]";
        }
        if (probe.isExactMatch(baseline)) {
            return prefix + "：与原始响应一致";
        }
        if (probe.isCompatibleWith(baseline)) {
            return prefix + "：与原始响应兼容";
        }
        if (probe.statusCode != baseline.statusCode) {
            return prefix + "：状态码 " + probe.statusCode;
        }
        return prefix + "：正文长度变化 " + (probe.bodyLength - baseline.bodyLength);
    }

    //提取请求头中 Referer 的值，只在头部区域查找（防止误匹配正文内容），不存在返回 null
    private String getRefererValue(byte[] request) {
        if (request == null) {
            return null;
        }
        String req = helpers.bytesToString(request);
        int bodyIdx = req.indexOf("\r\n\r\n");
        String header = bodyIdx >= 0 ? req.substring(0, bodyIdx) : req;
        Matcher m = REFERER_HEADER_PATTERN.matcher(header);
        if (m.find()) {
            String value = m.group(1);
            return value == null ? null : value.trim();
        }
        return null;
    }

    //构造修改了 Referer 头的请求包。只在头部区域替换；头部无 Referer 时在请求行后插入。
    //使用 quoteReplacement 防止 Referer 值中的 $、\ 破坏替换，保证字节级往返安全（不改动正文编码）
    private byte[] buildRefererRequest(byte[] request, String newRefererValue) {
        String req = helpers.bytesToString(request);
        int bodyIdx = req.indexOf("\r\n\r\n");
        String header = bodyIdx >= 0 ? req.substring(0, bodyIdx) : req;
        String body = bodyIdx >= 0 ? req.substring(bodyIdx) : "";
        Matcher m = REFERER_HEADER_PATTERN.matcher(header);
        if (m.find()) {
            header = m.replaceFirst(Matcher.quoteReplacement("Referer: " + newRefererValue));
        } else {
            int lineEnd = header.indexOf("\r\n");
            if (lineEnd < 0) {
                return null;
            }
            header = header.substring(0, lineEnd + 2) + "Referer: " + newRefererValue + "\r\n" + header.substring(lineEnd + 2);
        }
        return helpers.stringToBytes(header + body);
    }

    private boolean isGarbledParameter(String name, String value) {
        if (name == null || name.isEmpty()) return true;
        if (name.length() > 200) return true;
        int printable = 0;
        int controlChars = 0;
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (c >= 0x20 && c <= 0x7E) {
                printable++;
            } else if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') {
                controlChars++;
            }
        }
        if (controlChars > 0) return true;
        if ((double) printable / name.length() < 0.5) return true;
        if (value != null) {
            if (value.length() > 5000) return true;
            int valPrintable = 0;
            int valControl = 0;
            for (int i = 0; i < Math.min(value.length(), 200); i++) {
                char c = value.charAt(i);
                if (c >= 0x20 && c <= 0x7E) valPrintable++;
                else if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') valControl++;
            }
            if (valControl > 0) return true;
            if (value.length() <= 200 && (double) valPrintable / value.length() < 0.3) return true;
        }
        return false;
    }

    private int getQuoteCount(String payload) {
        if (payload == null || payload.length() < 1 || payload.length() > 4) {
            return 0;
        }
        for (int i = 0; i < payload.length(); i++) {
            if (payload.charAt(i) != '\'') {
                return 0;
            }
        }
        return payload.length();
    }

    private QuoteParityEvaluator.ResponseProfile buildResponseProfile(byte[] response) {
        if (response == null) {
            return null;
        }
        try {
            IResponseInfo responseInfo = helpers.analyzeResponse(response);
            int bodyOffset = responseInfo.getBodyOffset();
            if (bodyOffset < 0 || bodyOffset > response.length) {
                return null;
            }
            byte[] body = new byte[response.length - bodyOffset];
            System.arraycopy(response, bodyOffset, body, 0, body.length);
            String bodyText = new String(body, StandardCharsets.UTF_8);
            String errorMarker = findDatabaseErrorMarker(bodyText);
            boolean hasTypeConversion = isTypeConversionError(bodyText);
            String typeConversionMarker = hasTypeConversion ? findTypeConversionClass(bodyText) : null;
            return new QuoteParityEvaluator.ResponseProfile(
                    responseInfo.getStatusCode(), body.length, MD5(bodyText),
                    errorMarker != null, errorMarker,
                    hasTypeConversion, typeConversionMarker);
        } catch (Exception exception) {
            stdout.println("无法解析响应：" + exception);
            return null;
        }
    }

    private String findDatabaseErrorMarker(String bodyText) {
        String normalized = bodyText.toLowerCase();
        String[][] errorMarkers = {
                {"SQLSTATE", "sqlstate"},
                {"SQLException", "sqlexception"},
                {"PDOException", "pdoexception"},
                {"SQL syntax error", "you have an error in your sql syntax"},
                {"MariaDB server version", "mariadb server version"},
                {"PostgreSQL", "postgresql"},
                {"PG::SyntaxError", "pg::syntaxerror"},
                {"ORA-", "ora-"},
                {"SQLite error", "sqlite error"},
                {"unclosed quotation mark", "unclosed quotation mark"},
                {"SQL Server", "microsoft ole db provider for sql server"}
        };
        for (String[] errorMarker : errorMarkers) {
            if (normalized.contains(errorMarker[1])) {
                return errorMarker[0];
            }
        }
        return null;
    }

    private boolean isTypeConversionError(String bodyText) {
        String normalized = bodyText.toLowerCase();
        String[] typeConversionSignatures = {
                "numberformatexception",
                "java.lang.integer",
                "java.lang.long",
                "java.lang.double",
                "java.lang.float",
                "java.lang.short",
                "java.lang.byte",
                "java.lang.boolean",
                "java.lang.number",
                "for input string:",
                "cannot be cast to",
                "classcastexception",
                "java.util.date",
                "java.time.format.datetimeparseexception",
                "java.lang.illegalargumentexception",
                "methodargumenttypemismatchexception",
                "bindexception",
                "constraintviolationexception",
                "jsonmappingexception",
                "jsonparseexception",
                "java.math.bigdecimal",
                "java.math.biginteger",
                "parseexception",
                "textparseexception"
        };
        for (String signature : typeConversionSignatures) {
            if (normalized.contains(signature)) {
                return true;
            }
        }
        return false;
    }

    private String findTypeConversionClass(String bodyText) {
        String normalized = bodyText.toLowerCase();
        if (normalized.contains("numberformatexception")) return "NumberFormatException";
        if (normalized.contains("java.lang.integer")) return "java.lang.Integer";
        if (normalized.contains("java.lang.long")) return "java.lang.Long";
        if (normalized.contains("java.lang.double")) return "java.lang.Double";
        if (normalized.contains("java.lang.float")) return "java.lang.Float";
        if (normalized.contains("java.lang.short")) return "java.lang.Short";
        if (normalized.contains("java.lang.byte")) return "java.lang.Byte";
        if (normalized.contains("java.lang.boolean")) return "java.lang.Boolean";
        if (normalized.contains("java.lang.number")) return "java.lang.Number";
        if (normalized.contains("methodargumenttypemismatchexception")) return "MethodArgumentTypeMismatchException";
        if (normalized.contains("bindexception")) return "BindException";
        if (normalized.contains("constraintviolationexception")) return "ConstraintViolationException";
        if (normalized.contains("jsonmappingexception")) return "JsonMappingException";
        if (normalized.contains("jsonparseexception")) return "JsonParseException";
        if (normalized.contains("java.math.bigdecimal")) return "java.math.BigDecimal";
        if (normalized.contains("java.math.biginteger")) return "java.math.BigInteger";
        if (normalized.contains("parseexception")) return "ParseException";
        if (normalized.contains("textparseexception")) return "TextParseException";
        if (normalized.contains("classcastexception")) return "ClassCastException";
        if (normalized.contains("datetimeparseexception")) return "DateTimeParseException";
        return "类型转换";
    }

    private String describeQuoteProbe(int quoteCount, QuoteParityEvaluator.ResponseProfile baseline,
                                      QuoteParityEvaluator.ResponseProfile probe) {
        String prefix = quoteCount % 2 == 0 ? "偶数引号" : "奇数引号";
        if (probe.hasDatabaseError && !baseline.hasDatabaseError) {
            return prefix + "出现关键词[" + probe.databaseErrorMarker + "]" + "→大概率是SQL注入";
        }
        if (probe.hasOnlyTypeConversionNotRealDbError()) {
            return prefix + "大概率误报：类型转换错误[" + probe.typeConversionMarker + "]";
        }
        if (probe.isExactMatch(baseline)) {
            return prefix + "与原始响应一致";
        }
        if (probe.isCompatibleWith(baseline)) {
            return prefix + "正常（状态/正文长度一致）";
        }
        if (probe.statusCode != baseline.statusCode) {
            return prefix + "异常：状态码 " + probe.statusCode;
        }
        return prefix + "异常：正文长度变化 " + (probe.bodyLength - baseline.bodyLength);
    }

    private static final class QuoteParityEvaluator {
        private QuoteParityEvaluator() {
        }

        static Result evaluate(ResponseProfile baseline, ResponseProfile[] probes) {
            if (baseline == null || baseline.hasDatabaseError || probes == null || probes.length != 4) {
                return Result.inconclusive("基线或引号响应不完整");
            }
            for (ResponseProfile probe : probes) {
                if (probe == null) {
                    return Result.inconclusive("引号响应缺失");
                }
            }

            boolean oddOneAbnormal = probes[0].isAbnormalComparedWith(baseline);
            boolean oddThreeAbnormal = probes[2].isAbnormalComparedWith(baseline);
            boolean evenTwoCompatible = probes[1].isCompatibleWith(baseline);
            boolean evenFourCompatible = probes[3].isCompatibleWith(baseline);
            if (!oddOneAbnormal || !oddThreeAbnormal || !evenTwoCompatible || !evenFourCompatible) {
                return Result.noFinding();
            }
            if (probes[0].hasOnlyTypeConversionNotRealDbError()
                    && probes[2].hasOnlyTypeConversionNotRealDbError()) {
                return Result.inconclusive("奇数引号为类型转换错误，非数据库报错，不判定为SQL注入");
            }

            boolean oddDbMatch = probes[0].hasRealDatabaseErrorNotTypeConversion()
                    && probes[2].hasRealDatabaseErrorNotTypeConversion()
                    && probes[0].databaseErrorMarker != null
                    && probes[0].databaseErrorMarker.equals(probes[2].databaseErrorMarker);
            if (oddDbMatch) {
                if (!probes[1].hasSameBehaviorAs(probes[3])) {
                    return Result.noFinding();
                }
                if (probes[0].statusCode != probes[2].statusCode) {
                    return Result.noFinding();
                }
                if (probes[0].hasSameBehaviorAs(probes[1])) {
                    return Result.noFinding();
                }
            } else {
                if (!probes[0].hasSameBehaviorAs(probes[2]) || !probes[1].hasSameBehaviorAs(probes[3])) {
                    return Result.noFinding();
                }
                if (probes[0].hasSameBehaviorAs(probes[1])) {
                    return Result.noFinding();
                }
            }

            boolean exactEvenMatch = probes[1].isExactMatch(baseline) && probes[3].isExactMatch(baseline);
            boolean oddProbesHaveRealDbError = probes[0].hasRealDatabaseErrorNotTypeConversion()
                    && probes[2].hasRealDatabaseErrorNotTypeConversion();

            String dbKeyword = probes[0].hasDatabaseError ? probes[0].databaseErrorMarker
                    : probes[2].hasDatabaseError ? probes[2].databaseErrorMarker : null;
            String message;
            if (oddProbesHaveRealDbError && dbKeyword != null) {
                message = exactEvenMatch
                        ? "高度可信：出现关键词[" + dbKeyword + "]→大概率是SQL注入，偶数引号匹配原始响应"
                        : "高度可信：出现关键词[" + dbKeyword + "]→大概率是SQL注入";
            } else {
                return Result.noFinding();
            }
            return Result.suspicious(message, exactEvenMatch);
        }

        private static final class ResponseProfile {
            final int statusCode;
            final int bodyLength;
            final String bodyFingerprint;
            final boolean hasDatabaseError;
            final String databaseErrorMarker;
            final boolean hasTypeConversionError;
            final String typeConversionMarker;

            ResponseProfile(int statusCode, int bodyLength, String bodyFingerprint,
                            boolean hasDatabaseError, String databaseErrorMarker,
                            boolean hasTypeConversionError, String typeConversionMarker) {
                this.statusCode = statusCode;
                this.bodyLength = bodyLength;
                this.bodyFingerprint = bodyFingerprint;
                this.hasDatabaseError = hasDatabaseError;
                this.databaseErrorMarker = databaseErrorMarker;
                this.hasTypeConversionError = hasTypeConversionError;
                this.typeConversionMarker = typeConversionMarker;
            }

            boolean isCompatibleWith(ResponseProfile baseline) {
                return statusCode == baseline.statusCode
                        && bodyLength == baseline.bodyLength
                        && !hasNewDatabaseErrorComparedWith(baseline);
            }

            boolean isAbnormalComparedWith(ResponseProfile baseline) {
                return statusCode != baseline.statusCode
                        || bodyLength != baseline.bodyLength
                        || hasNewDatabaseErrorComparedWith(baseline);
            }

            boolean hasSameBehaviorAs(ResponseProfile other) {
                return statusCode == other.statusCode
                        && bodyLength == other.bodyLength
                        && hasDatabaseError == other.hasDatabaseError
                        && equalsNullable(databaseErrorMarker, other.databaseErrorMarker)
                        && hasTypeConversionError == other.hasTypeConversionError
                        && equalsNullable(typeConversionMarker, other.typeConversionMarker);
            }

            boolean isExactMatch(ResponseProfile other) {
                return isCompatibleWith(other) && equalsNullable(bodyFingerprint, other.bodyFingerprint);
            }

            private boolean hasNewDatabaseErrorComparedWith(ResponseProfile baseline) {
                return hasDatabaseError && !baseline.hasDatabaseError;
            }

            boolean hasRealDatabaseErrorNotTypeConversion() {
                return hasDatabaseError;
            }

            boolean hasOnlyTypeConversionNotRealDbError() {
                return hasTypeConversionError && !hasDatabaseError;
            }

            private static boolean equalsNullable(Object left, Object right) {
                return left == null ? right == null : left.equals(right);
            }
        }

        private static final class Result {
            final boolean suspicious;
            final boolean exactEvenMatch;
            final String message;

            private Result(boolean suspicious, boolean exactEvenMatch, String message) {
                this.suspicious = suspicious;
                this.exactEvenMatch = exactEvenMatch;
                this.message = message;
            }

            static Result suspicious(String message, boolean exactEvenMatch) {
                return new Result(true, exactEvenMatch, message);
            }

            static Result noFinding() {
                return new Result(false, false, "");
            }

            static Result inconclusive(String message) {
                return new Result(false, false, message);
            }
        }
    }

    private static final class OrderByEvaluator {
        private OrderByEvaluator() {
        }

        static Result evaluate(QuoteParityEvaluator.ResponseProfile baseline,
                               QuoteParityEvaluator.ResponseProfile[] probes) {
            if (baseline == null || baseline.hasDatabaseError || probes == null || probes.length != 4) {
                return Result.noFinding();
            }
            for (QuoteParityEvaluator.ResponseProfile probe : probes) {
                if (probe == null) {
                    return Result.noFinding();
                }
            }

            boolean firstNormal = probes[0].isCompatibleWith(baseline);
            boolean secondError = probes[1].isAbnormalComparedWith(baseline);
            boolean thirdNormal = probes[2].isCompatibleWith(baseline);
            boolean fourthError = probes[3].isAbnormalComparedWith(baseline);
            if (!firstNormal || !secondError || !thirdNormal || !fourthError) {
                return Result.noFinding();
            }
            if (probes[1].hasOnlyTypeConversionNotRealDbError()
                    && probes[3].hasOnlyTypeConversionNotRealDbError()) {
                return Result.inconclusive("ORDER BY 异常探针为类型转换错误，非数据库报错，不判定为SQL注入");
            }
            if (!probes[0].hasSameBehaviorAs(probes[2]) || !probes[1].hasSameBehaviorAs(probes[3])) {
                return Result.noFinding();
            }
            if (probes[0].hasSameBehaviorAs(probes[1])) {
                return Result.noFinding();
            }

            boolean exactNormalMatch = probes[0].isExactMatch(baseline) && probes[2].isExactMatch(baseline);
            boolean errorProbesHaveRealDbError = probes[1].hasRealDatabaseErrorNotTypeConversion()
                    && probes[3].hasRealDatabaseErrorNotTypeConversion();

            String dbKeyword = probes[1].hasDatabaseError ? probes[1].databaseErrorMarker
                    : probes[3].hasDatabaseError ? probes[3].databaseErrorMarker : null;
            String message;
            if (errorProbesHaveRealDbError && dbKeyword != null) {
                message = exactNormalMatch
                        ? "高度可信：出现关键词[" + dbKeyword + "]→大概率是SQL注入，正常探针匹配原始响应"
                        : "高度可信：出现关键词[" + dbKeyword + "]→大概率是SQL注入";
            } else {
                return Result.noFinding();
            }
            return Result.suspicious(message);
        }

        private static final class Result {
            final boolean suspicious;
            final String message;

            private Result(boolean suspicious, String message) {
                this.suspicious = suspicious;
                this.message = message;
            }

            static Result suspicious(String message) {
                return new Result(true, message);
            }

            static Result noFinding() {
                return new Result(false, "");
            }

            static Result inconclusive(String message) {
                return new Result(false, message);
            }
        }
    }

    public static String MD5(String key) {
        char hexDigits[] = {
                '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
        };
        try {
            byte[] btInput = key.getBytes(StandardCharsets.UTF_8);
            // 获得MD5摘要算法的 MessageDigest 对象
            MessageDigest mdInst = MessageDigest.getInstance("MD5");
            // 使用指定的字节更新摘要
            mdInst.update(btInput);
            // 获得密文
            byte[] md = mdInst.digest();
            // 把密文转换成十六进制的字符串形式
            int j = md.length;
            char str[] = new char[j * 2];
            int k = 0;
            for (int i = 0; i < j; i++) {
                byte byte0 = md[i];
                str[k++] = hexDigits[byte0 >>> 4 & 0xf];
                str[k++] = hexDigits[byte0 & 0xf];
            }
            return new String(str);
        } catch (Exception e) {
            return null;
        }
    }


}
