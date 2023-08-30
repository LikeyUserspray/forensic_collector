#include <FL/Fl.H>
#include <FL/Fl_Window.H>
#include <FL/Fl_Input.H>
#include <FL/Fl_Button.H>
#include <FL/Fl_Output.H>
#include <FL/Fl_Check_Button.H>
#include <FL/Fl_Text_Display.H>
#include <FL/Fl_Text_Buffer.H>
#include <FL/Fl_Native_File_Chooser.H> 
#include <fstream>
#include <string>

Fl_Text_Buffer* buffer;
Fl_Input* subject_info;
Fl_Input* selected_info;
Fl_Input* taken_time_info;
Fl_Window* export_win;
std::string Path = "./";

void save_Data(Fl_Widget* w, void* data) {
    /*
    //���� ��� ����
    Fl_Native_File_Chooser chooser;
    chooser.title("Save As");
    chooser.type(Fl_Native_File_Chooser::BROWSE_DIRECTORY);
    if (chooser.show() == 0) {
        const char* Path = chooser.filename();
        std::string baseDir(Path);
    }
    */
    // �߰� ���� �Է�
    void** widgets = (void**)data;
    Fl_Output* date_output = (Fl_Output*)widgets[0];
    Fl_Output* investigator_output = (Fl_Output*)widgets[1];
    std::string date = date_output->value();
    std::string investigator = investigator_output->value();
    std::string subject = subject_info->value();
    std::string selected = selected_info->value();
    std::string time = taken_time_info->value();
    std::string artifacts = buffer->text();

    // info_.txt �� ���� ����
    std::ofstream infoFile(Path + "info_.txt");
    infoFile << "Date: " << date << "\n";
    infoFile << "Investigator: " << investigator << "\n";
    infoFile << "Subject: " << subject << "\n";
    infoFile << "Selected Targets: " << selected << "\n";
    infoFile << "Time Taken: " << time << "\n";
    infoFile.close();

    // üũ�� �� ��Ƽ��Ʈ�� �� ��Ƽ������ �̸����� ���� ����
    if (artifacts.find("$MFT") != std::string::npos) {
        std::ofstream mftFile(Path + "$MFT.txt");
        mftFile << "Real $MFT...";  // ���� ���� �����ڸ�
        mftFile.close();
    }

    if (artifacts.find("Event Log") != std::string::npos) {
        std::ofstream eventLogFile(Path+"EventLog.txt");
        eventLogFile << "Real Event Log...";  // ���� ���� �����ڸ�
        eventLogFile.close();
    }

    if (artifacts.find("Browser History") != std::string::npos) {
        std::ofstream browserHistoryFile(Path+"BrowserHistory.txt");
        browserHistoryFile << "Real Browser History...";  // ���� ���� �����ڸ�
        browserHistoryFile.close();
    }

    //���� �� �Ǹ� save â �Ⱥ��̰�
    if (export_win) {
        export_win->hide();
    }
}

// Callback for 'Export' button - ���� ���� ���
void export_Data(Fl_Widget * w, void* data) {
    export_win = new Fl_Window(300, 200, "Additional Information");

    subject_info = new Fl_Input(100, 10, 200, 30, "subject_info:");
    selected_info = new Fl_Input(100, 50, 200, 30, "selected_info:");
    taken_time_info = new Fl_Input(100, 90, 200, 30, "taken_time:");

    Fl_Button* save_button = new Fl_Button(100, 130, 80, 30, "Save");
    save_button->callback(save_Data, data);

    export_win->end();
    export_win->show();

}

//üũ�ڽ� Ŭ�� �� ���� ��� ��ȯ
void updateTextDisplay(Fl_Widget* w, void* data) {
    Fl_Check_Button* button = (Fl_Check_Button*)w;
    const char* label = button->label();

    if (button->value()) {  // if checked
        buffer->append(label);
        buffer->append("\n");
    }
    else {  // if unchecked
     //�켱�� ������ ��� �����͸� �����ϰ� ��...üũ->üũ ǰ -> üũ �ϸ� ������ ���� ������ ����! �̰Ŵ� �� ���Ŀ� ����!!
        buffer->remove(0, buffer->length());
    }
}

// Callback for 'Input' button ....main�Լ����� ���� outputâ�� ������ �ִ�. Input ��ư�� ������ Inputâ�� �������� Output â�� ��Ÿ������  
void transferInputToOutput(Fl_Widget* w, void* data) {
    Fl_Input* date_input = (Fl_Input*)(((void**)data)[0]);
    Fl_Input* investigator_input = (Fl_Input*)(((void**)data)[1]);
    Fl_Output* date_output = (Fl_Output*)(((void**)data)[2]);
    Fl_Output* investigator_output = (Fl_Output*)(((void**)data)[3]);

    date_output->value(date_input->value());
    investigator_output->value(investigator_input->value());

    date_input->hide();
    investigator_input->hide();

    date_output->show();
    investigator_output->show();

    date_output->redraw();
    investigator_output->redraw();
}

int main() {
    //��ü �� UI
    Fl_Window win(700, 500, "Artifacts_Collector");

    //����â_UI
    Fl_Input date_input(120, 30, 200, 30, "Date:");
    Fl_Input investigator_input(120, 90, 200, 30, "Investigator:");

    Fl_Output date_output(120, 30, 200, 30, "Date:");
    Fl_Output investigator_output(120, 90, 200, 30, "Investigator:");

    //üũ�ڽ�_UI
    Fl_Check_Button MFT_CheckBox(120, 150, 100, 30, "$MFT");
    Fl_Check_Button eventLog_CheckBox(230, 150, 100, 30, "Event Log");
    Fl_Check_Button browserHistory_CheckBox(340, 150, 150, 30, "Browser History");

    //üũ�ڽ� ���� ��� â
    Fl_Text_Display text_display(120, 200, 400, 200);
    buffer = new Fl_Text_Buffer();
    text_display.buffer(buffer);

    //üũ�ڽ� �κ� ����
    MFT_CheckBox.callback(updateTextDisplay);
    eventLog_CheckBox.callback(updateTextDisplay);
    browserHistory_CheckBox.callback(updateTextDisplay);

    //���� â ���� �� ��� ����
    date_output.color(FL_LIGHT2);
    investigator_output.color(FL_LIGHT2);
    date_output.textcolor(FL_GRAY);
    investigator_output.textcolor(FL_GRAY);
    date_output.hide();
    investigator_output.hide();

    //Input ��ư 
    void* widgets[] = { &date_input, &investigator_input, &date_output, &investigator_output };
    Fl_Button Input_button(350, 90, 80, 30, "Input");
    Input_button.callback(transferInputToOutput, widgets);

    //export ��ư
    void* exportWidgets[] = { &date_output, &investigator_output };
    Fl_Button Export_button(10, 460, 680, 30, "Export");
    Export_button.callback(export_Data, exportWidgets);

    win.end();
    win.show();

    return Fl::run();
}