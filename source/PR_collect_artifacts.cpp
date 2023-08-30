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
    //저장 경로 설정
    Fl_Native_File_Chooser chooser;
    chooser.title("Save As");
    chooser.type(Fl_Native_File_Chooser::BROWSE_DIRECTORY);
    if (chooser.show() == 0) {
        const char* Path = chooser.filename();
        std::string baseDir(Path);
    }
    */
    // 추가 정보 입력
    void** widgets = (void**)data;
    Fl_Output* date_output = (Fl_Output*)widgets[0];
    Fl_Output* investigator_output = (Fl_Output*)widgets[1];
    std::string date = date_output->value();
    std::string investigator = investigator_output->value();
    std::string subject = subject_info->value();
    std::string selected = selected_info->value();
    std::string time = taken_time_info->value();
    std::string artifacts = buffer->text();

    // info_.txt 로 정보 저장
    std::ofstream infoFile(Path + "info_.txt");
    infoFile << "Date: " << date << "\n";
    infoFile << "Investigator: " << investigator << "\n";
    infoFile << "Subject: " << subject << "\n";
    infoFile << "Selected Targets: " << selected << "\n";
    infoFile << "Time Taken: " << time << "\n";
    infoFile.close();

    // 체크된 각 아티팩트를 각 아티팩으의 이름으로 내용 저장
    if (artifacts.find("$MFT") != std::string::npos) {
        std::ofstream mftFile(Path + "$MFT.txt");
        mftFile << "Real $MFT...";  // 실제 정보 넣을자리
        mftFile.close();
    }

    if (artifacts.find("Event Log") != std::string::npos) {
        std::ofstream eventLogFile(Path+"EventLog.txt");
        eventLogFile << "Real Event Log...";  // 실제 정보 넣을자리
        eventLogFile.close();
    }

    if (artifacts.find("Browser History") != std::string::npos) {
        std::ofstream browserHistoryFile(Path+"BrowserHistory.txt");
        browserHistoryFile << "Real Browser History...";  // 실제 정보 넣을자리
        browserHistoryFile.close();
    }

    //저장 다 되면 save 창 안보이게
    if (export_win) {
        export_win->hide();
    }
}

// Callback for 'Export' button - 파일 저장 기능
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

//체크박스 클릭 시 마다 출력 변환
void updateTextDisplay(Fl_Widget* w, void* data) {
    Fl_Check_Button* button = (Fl_Check_Button*)w;
    const char* label = button->label();

    if (button->value()) {  // if checked
        buffer->append(label);
        buffer->append("\n");
    }
    else {  // if unchecked
     //우선은 버퍼의 모든 데이터를 삭제하게 둠...체크->체크 품 -> 체크 하면 내용이 없는 문제가 있음! 이거는 음 추후에 수정!!
        buffer->remove(0, buffer->length());
    }
}

// Callback for 'Input' button ....main함수에서 보면 output창이 숨겨져 있다. Input 버튼을 누르면 Input창이 숨겨지고 Output 창이 나타나도록  
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
    //전체 장 UI
    Fl_Window win(700, 500, "Artifacts_Collector");

    //정보창_UI
    Fl_Input date_input(120, 30, 200, 30, "Date:");
    Fl_Input investigator_input(120, 90, 200, 30, "Investigator:");

    Fl_Output date_output(120, 30, 200, 30, "Date:");
    Fl_Output investigator_output(120, 90, 200, 30, "Investigator:");

    //체크박스_UI
    Fl_Check_Button MFT_CheckBox(120, 150, 100, 30, "$MFT");
    Fl_Check_Button eventLog_CheckBox(230, 150, 100, 30, "Event Log");
    Fl_Check_Button browserHistory_CheckBox(340, 150, 150, 30, "Browser History");

    //체크박스 내용 출력 창
    Fl_Text_Display text_display(120, 200, 400, 200);
    buffer = new Fl_Text_Buffer();
    text_display.buffer(buffer);

    //체크박스 부분 실행
    MFT_CheckBox.callback(updateTextDisplay);
    eventLog_CheckBox.callback(updateTextDisplay);
    browserHistory_CheckBox.callback(updateTextDisplay);

    //정보 창 색깔 및 출력 숨김
    date_output.color(FL_LIGHT2);
    investigator_output.color(FL_LIGHT2);
    date_output.textcolor(FL_GRAY);
    investigator_output.textcolor(FL_GRAY);
    date_output.hide();
    investigator_output.hide();

    //Input 버튼 
    void* widgets[] = { &date_input, &investigator_input, &date_output, &investigator_output };
    Fl_Button Input_button(350, 90, 80, 30, "Input");
    Input_button.callback(transferInputToOutput, widgets);

    //export 버튼
    void* exportWidgets[] = { &date_output, &investigator_output };
    Fl_Button Export_button(10, 460, 680, 30, "Export");
    Export_button.callback(export_Data, exportWidgets);

    win.end();
    win.show();

    return Fl::run();
}