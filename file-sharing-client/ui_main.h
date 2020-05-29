#ifndef UI_MAIN_H
#define UI_MAIN_H

#include <QMainWindow>
#include <QWidget>
#include <QToolBar>
#include <QSize>
#include <QPushButton>
#include <QTableWidget>
#include <QVBoxLayout>
#include <QHeaderView>
#include <QStatusBar>

#include "MainTable/maintable.h"

namespace UI {

class Ui_Main {
public:
    QWidget* centralWidget;
    QVBoxLayout* mainLayout;
    MainTableWidget* tableWidget;
    QToolBar* toolBar;
    QPushButton* connectToServerButton;
    QPushButton* testButton;
    QStatusBar* statusBar;

    const int width = 400;
    const int height = 300;
    const QSize buttonSize = QSize(25, 30);

    void setupUi(QMainWindow* mainWindow) {
        if (mainWindow->objectName().isEmpty()) {
            mainWindow->setObjectName("mainWindow");
        }

        mainWindow->resize(width, height);
        centralWidget = new QWidget(mainWindow);
        centralWidget->setObjectName("centralWidget");

        mainLayout = new QVBoxLayout(centralWidget);

        tableWidget = new MainTableWidget(centralWidget);
        tableWidget->setShowGrid(false);
        tableWidget->horizontalHeader()->setStretchLastSection(true);
        tableWidget->verticalHeader()->setVisible(false);
        tableWidget->verticalHeader()->setSectionResizeMode(QHeaderView::Fixed);
        tableWidget->verticalHeader()->setDefaultSectionSize(16);
        tableWidget->setColumnCount(3);
        tableWidget->setHorizontalHeaderLabels(QStringList() << "File name" << "Size" << "Type");
        tableWidget->setSortingEnabled(false);
        tableWidget->setSelectionBehavior(QTableWidget::SelectRows);
        tableWidget->setSelectionMode(QAbstractItemView::SingleSelection);
        tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
        tableWidget->setContextMenuPolicy(Qt::CustomContextMenu);
        mainLayout->addWidget(tableWidget);
        tableWidget->setDragEnabled(true);
        tableWidget->setAcceptDrops(true);

        statusBar = new QStatusBar(mainWindow);

        toolBar = new QToolBar(centralWidget);
        toolBar->setObjectName("toolBar");
        toolBar->setMovable(false);

        connectToServerButton = new QPushButton(toolBar);
        connectToServerButton->setText("Connect");
        toolBar->addWidget(connectToServerButton);

        testButton = new QPushButton(toolBar);
        testButton->setText("Test Request");
        toolBar->addWidget(testButton);

        mainWindow->addToolBar(toolBar);
        mainWindow->setCentralWidget(centralWidget);
        mainWindow->setStatusBar(statusBar);
    }

    ~Ui_Main() {
        delete centralWidget;
    }
};

}

#endif // UI_MAIN_H
