package com.minderv.utils;

import com.minderv.core.model.Report;
import org.apache.poi.xwpf.usermodel.*;
import java.io.FileOutputStream;
import java.io.IOException;

public class FileUtils {
    public static void exportToWord(Report report) throws IOException {
        try (XWPFDocument doc = new XWPFDocument()) {
            // 标题
            XWPFParagraph title = doc.createParagraph();
            title.setAlignment(ParagraphAlignment.CENTER);
            XWPFRun titleRun = title.createRun();
            titleRun.setText("网络安全评估报告");
            titleRun.setBold(true);
            titleRun.setFontSize(16);

            // 内容
            addSection(doc, "漏洞发现", report.findings().toString());
            addSection(doc, "建议措施", String.join("\n", report.recommendations()));

            // 保存文件
            doc.write(new FileOutputStream("Assessment_Report.docx"));
        }
    }

    private static void addSection(XWPFDocument doc, String header, String content) {
        XWPFParagraph para = doc.createParagraph();
        XWPFRun run = para.createRun();
        run.setText(header + ":");
        run.setBold(true);
        run.addBreak();

        XWPFParagraph contentPara = doc.createParagraph();
        contentPara.createRun().setText(content);
    }
}