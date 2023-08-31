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
#include <filesystem>
#include <iostream>
#include <vector>


Fl_Text_Buffer* buffer;
Fl_Input* subject_info;
Fl_Input* selected_info;
Fl_Input* taken_time_info;
Fl_Window* export_win;
std::string Path = "./";

namespace fs = std::filesystem;
//-------------------------------------------------------------------------------------------------------------
//아티팩트 수집하는 함수들-------------------------------------------------------------------------------------
// 
// EventLog 파일을 복사하는 함수
bool CopyEventLogFiles(const std::wstring& eventLogSourceDir, const std::wstring& destDir) {
    int Event_log_files_count = 0;
    for (const auto& entry : fs::directory_iterator(eventLogSourceDir)) {
        if (entry.path().extension() == L".evtx") {
            std::wstring destPath = destDir + L"\\" + entry.path().filename().wstring();
            if (!CopyFile(entry.path().c_str(), destPath.c_str(), FALSE)) {
                std::cerr << "Error copying event log file: " << GetLastError() << std::endl;
                return false;
            }
            Event_log_files_count++;
        }
    }
    std::cout << "Total files copied: " << Event_log_files_count << std::endl; // "복사된 파일 수 출력" 이걸 나중에 출력창에 해줘야지..!
    return true;
}

// Prefetch 파일을 복사하는 함수
bool CopyPrefetchFiles(const std::wstring& prefetchSourceDir, const std::wstring& destDir) {
    for (const auto& entry : fs::directory_iterator(prefetchSourceDir)) {
        if (entry.path().extension() == L".pf") {
            std::wstring destPath = destDir + L"\\" + entry.path().filename().wstring();
            if (!CopyFile(entry.path().c_str(), destPath.c_str(), FALSE)) {
                std::cerr << "Error copying prefetch file: " << GetLastError() << std::endl;
                return false;
            }
        }
    }
    return true;
}
//---------------------------------------------------------------------------------------------------------------
//Input 버튼 눌렀을 때 아티팩트 수집해서 각 폴더에 저장----------------------------------------------------------
void Copy_eventlog_Filesave() {
    std::wstring sourceDir = L"C:\\Windows\\System32\\winevt\\Logs";
    std::wstring baseDestDir = L"./";
    std::wstring eventLogFolder = L"\\Event_Logs"; // 새로 생성할 폴더 이름
    try {
        std::filesystem::create_directory(baseDestDir + eventLogFolder);
    }
    catch (std::filesystem::filesystem_error& e) {
        std::cout << "Exception caught: " << e.what() << '\n';
        return ; // 또는 적절한 오류 처리
    }
    std::wstring destDir = baseDestDir + eventLogFolder; // 이벤트 로그를 저장할 디렉토리
    if (CopyEventLogFiles(sourceDir, destDir)) {
        std::cout << "Files copied successfully!" << std::endl;
        return ;
    }
    else {
        std::cout << "Failed to copy files." << std::endl;
        return ;
    }
}


//---------------------------------------------------------------------------------------------------------------
//export 버튼 관련 기능 들!! ++ save 버튼 눌렀을 때 -------------------------------------------------------------
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

    // 체크된 각 아티팩트를 각 아티팩트의 이름으로 내용 저장
    if (artifacts.find("$MFT") != std::string::npos) {
        std::ofstream mftFile(Path + "$MFT.txt");
        mftFile << "Real $MFT...";  // 실제 정보 넣을자리
        mftFile.close();
    }

    if (artifacts.find("Event Log") != std::string::npos) {
        std::ofstream eventLogFile(Path+"EventLog.txt");
        eventLogFile << buffer->text();
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

//---------------------------------------------------------------------------------------------------------------
//체크 박스 선택 부분--------------------------------------------------------------------------------------------
//체크박스 클릭 시 마다 출력 변환
void updateTextDisplay(Fl_Widget* w, void* data) {
    Fl_Check_Button* button = (Fl_Check_Button*)w;
    const char* label = button->label();

    if (button->value()) {  // if checked
        buffer->append(label);
        buffer->append("\n");


        if (std::string(label) == "Event Log") {
            // Event Log 체크박스가 클릭되었다면
            std::wstring dirPath = L"./Event_Logs";  // 디렉토리 경로

            buffer->append("\n");
            for (const auto& entry : std::filesystem::directory_iterator(dirPath)) {
                if (entry.path().extension() == L".evtx") {
                    // 파일 이름을 리스트에 추가
                    std::string fileName = entry.path().filename().string();
                    buffer->append(fileName.c_str());
                    buffer->append("\n");
                }
            }
        }
    }
    else {  // if unchecked
        buffer->text("");
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

    //아티팩트 수집 및 저장 실행.!!
    Copy_eventlog_Filesave();

}


//---------------------------------------------------------------------------------------------------------------
//메인함수------------------------------------------------------------------------------------------------------
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
