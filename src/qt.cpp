#include "pgpp/pg_qt.h"
#include "pgpp/pg_connection.h"
#include "pgpp/pg_types.h"
#include <QApplication>
#include <QMessageBox>
#include <QSettings>
#include <QDate>
#include <QLabel>
#include <QLineEdit>
#include <QAbstractButton>
#include <QPushButton>
#include <QVBoxLayout>
#include <QFormLayout>
#include <QPlainTextEdit>
#include <QDialogButtonBox>
#include <QJsonValue>

namespace pg
{

void changePassword()
{
    std::unique_ptr<QDialog> dlg(new QDialog());
    dlg->setWindowFlags(Qt::Window | Qt::CustomizeWindowHint | Qt::WindowTitleHint | Qt::WindowCloseButtonHint);
    QVBoxLayout *l = new QVBoxLayout();
    QFormLayout *fl = new QFormLayout();
    QDialogButtonBox *btnBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    QObject::connect(btnBox, &QDialogButtonBox::rejected, dlg.get(), &QDialog::reject);

    QLineEdit *pass1 = new QLineEdit();
    pass1->setEchoMode(QLineEdit::Password);
    QLineEdit *pass2 = new QLineEdit();
    pass2->setEchoMode(QLineEdit::Password);
    QLabel *hint = new QLabel();
    hint->setStyleSheet("font-style: italic");

    QObject::connect(btnBox, &QDialogButtonBox::accepted, dlg.get(), [&]()
    {
        try
        {
            std::shared_ptr<pg::connection> cn = dbpool<pg::connection>::get()->get_connection(true);
            auto res = cn->exec("select session_user", nullptr);
            QString user = res->raw_value(0, 0);
            QString encPassword = pg::encrypt_password(pass1->text().toStdString(), user.toStdString()).c_str();
            if (encPassword.isEmpty())
                QMessageBox::critical(QApplication::activeWindow(),
                                      QObject::tr("Ошибка"),
                                      QObject::tr("PQencryptPassword вернула NULL"));
            else if (cn->exec(QString("ALTER ROLE \"%1\" ENCRYPTED PASSWORD '%2'").arg(user).arg(encPassword).
                              toUtf8().constData(), nullptr))
                dlg->accept();
        }
        catch (const std::exception &err)
        {
            QMessageBox::critical(QApplication::activeWindow(),
                                  QObject::tr("Ошибка"),
                                  QString::fromStdString(err.what()));
        }
    });

    fl->addRow(QObject::tr("Пароль"), pass1);
    fl->addRow(QObject::tr("Повтор пароля"), pass2);
    l->addLayout(fl);
    l->addWidget(hint);
    l->addSpacing(10);
    l->addWidget(btnBox);
    dlg->setLayout(l);
    dlg->adjustSize();

    std::function<void(QString)> onPassChanged = [&](QString)
    {
        QRegExp rx("((\\d\\D)|(\\D\\d))");
        if (pass1->text().length() < 6)
            hint->setText(QObject::tr("Длина пароля должна быть не менее 6 символов"));
        else if (!pass1->text().contains(rx))
            hint->setText(QObject::tr("В пароле должны быть буквы и цифры"));
        else if (pass1->text() != pass2->text())
            hint->setText(QObject::tr("Значения не совпадают"));
        else
            hint->clear();
        btnBox->button(QDialogButtonBox::Ok)->setEnabled(hint->text().isEmpty());
    };
    QObject::connect(pass1, &QLineEdit::textChanged, onPassChanged);
    QObject::connect(pass2, &QLineEdit::textChanged, onPassChanged);
    onPassChanged(QString());
    dlg->exec();
}

bool changeSettings()
{
    std::unique_ptr<QDialog> dlg(new QDialog());
    dlg->setWindowFlags(Qt::Window | Qt::CustomizeWindowHint | Qt::WindowTitleHint | Qt::WindowCloseButtonHint);

    QVBoxLayout *l = new QVBoxLayout();
    QLabel *cs_caption = new QLabel(QObject::tr("Строка подключения"));
    QPlainTextEdit *cs = new QPlainTextEdit();
    cs->setWordWrapMode(QTextOption::WrapAnywhere);
    QLabel *hint = new QLabel(QObject::tr("* используйте макросы %user% и %pass% вместо имени пользователя и пароля соответственно"));
    hint->setWordWrap(true);
    QDialogButtonBox *btnBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    QObject::connect(btnBox, &QDialogButtonBox::rejected, dlg.get(), &QDialog::reject);
    QObject::connect(btnBox, &QDialogButtonBox::accepted, dlg.get(), [&]()
    {
        QSettings settings;
        settings.setValue("ConnectionString", cs->toPlainText());
        dlg->accept();
    });

    QSettings settings;
    cs->setPlainText(settings.value(
                         "ConnectionString",
                         "host=<IP_address> port=5432 dbname=<db name> user=%user% "
                         "password=%pass% connect_timeout=3 requiressl=0").toString());
    l->addWidget(cs_caption);
    l->addWidget(cs);
    l->addWidget(hint);
    l->addWidget(btnBox);
    dlg->resize(700, 150);
    dlg->setLayout(l);
    return (dlg->exec() == QDialog::Accepted);
}

bool prepareDB(bool override)
{
    QSettings settings;

    auto p = dbpool<pg::connection>::get();
    p->onError([](const void *, const std::string &error, const void *)
    {
        if (error.empty())
            return;
        QMessageBox::critical(QApplication::activeWindow(),
                              QObject::tr("Ошибка"),
                              QString::fromStdString(error));
    });

    std::shared_ptr<pg::connection> cn;
    if (!override && p->state() != "")
    {
        cn = p->get_connection(true, false);
        if (!cn)
            return false;
        if (cn->exec("select 1", nullptr, false))
            return true;
    }

    bool try_more = true;
    while (try_more)
    {
        QString cs(settings.value("ConnectionString", "").toString());
        QString initial_cs = cs;

        if (cs.isEmpty())
        {
            try_more = changeSettings();
            continue;
        }

        QString un = settings.value("UserName", "").toString();
        cs.replace("%user%", un, Qt::CaseInsensitive);

        if (initial_cs.contains("%pass%", Qt::CaseInsensitive))
        {
            QString userName = initial_cs.contains("%user%", Qt::CaseInsensitive) ? un : QString();
            std::unique_ptr<QDialog> dlg(new QDialog());
            QVBoxLayout *l = new QVBoxLayout();
            QFormLayout *fl = new QFormLayout();
            QDialogButtonBox *btnBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
            QObject::connect(btnBox, &QDialogButtonBox::accepted, dlg.get(), &QDialog::accept);
            QObject::connect(btnBox, &QDialogButtonBox::rejected, dlg.get(), &QDialog::reject);

            if (initial_cs.contains("%user%", Qt::CaseInsensitive))
            {
                QLineEdit *userEditor = new QLineEdit(userName);
                fl->addRow(QObject::tr("Имя пользователя"), userEditor);
                QObject::connect(userEditor, &QLineEdit::textChanged, [&](QString value)
                {
                    userName = value;
                    btnBox->button(QDialogButtonBox::Ok)->setEnabled(!value.isEmpty());
                });
            }
            QLineEdit *passEditor = new QLineEdit();
            passEditor->setEchoMode(QLineEdit::Password);
            fl->addRow(QObject::tr("Пароль"), passEditor);
            l->addLayout(fl);
            l->addSpacing(10);
            l->addWidget(btnBox);
            dlg->setLayout(l);
            dlg->adjustSize();
            dlg->resize(300, dlg->height());
            if (!userName.isEmpty())
                passEditor->setFocus();

            while (try_more && dlg->exec() == QDialog::Accepted)
            {
                cs = initial_cs;
                cs.replace("%user%", userName, Qt::CaseInsensitive);
                cs.replace("%pass%", passEditor->text(), Qt::CaseInsensitive);
                p->set_connection_strings({cs.toStdString()});
                cn = p->get_connection(true);
                cn->on_error(nullptr);
                if (!cn->exec("select 1", nullptr, false))
                {
                    if (QMessageBox::warning(
                                QApplication::activeWindow(),
                                "Error",
                                QString::fromStdString(cn->last_error()).append(QObject::tr("\n\nПоказать настройки?")),
                                QMessageBox::Yes | QMessageBox::No, QMessageBox::Yes
                                ) == QMessageBox::Yes)
                    {
                        try_more = changeSettings();
                        break;
                    }
                    else
                        try_more = false;
                }
                else
                {
                    settings.setValue("UserName", userName);
                    try_more = false;
                    break;
                }
            }
            if (dlg->result() == QDialog::Rejected)
                try_more = false;
        }
        else
        {
            p->set_connection_strings({cs.toStdString()});
            cn = p->get_connection(true);
            cn->on_error(nullptr);
            if (!cn->exec("select 1", nullptr, false))
            {
                if (QMessageBox::warning(QApplication::activeWindow(),
                                         "Error",
                                         QString::fromStdString(cn->last_error()).append(QObject::tr("\n\nПоказать настройки?")),
                                         QMessageBox::Yes | QMessageBox::No,
                                         QMessageBox::Yes
                                         ) == QMessageBox::Yes)
                {
                    try_more = changeSettings();
                }
                else
                    try_more = false;
            }
            else
                try_more = false;
        }
    }
    return (cn && cn->is_connected());
}

QVariant::Type typeToVariantType(unsigned int sqlType)
{
    QVariant::Type type = QVariant::Invalid;
    switch (sqlType)
    {
    case INT2OID:
    case INT4OID:
        type = QVariant::Int;
        break;
    case OIDOID:
    case XIDOID:
    case CIDOID:
        type = QVariant::UInt;
        break;
    case ABSTIMEOID: // absolute, limited-range date and time (Unix system time)
    case INT8OID:
        type = QVariant::LongLong;
        break;
    case FLOAT4OID:
    case FLOAT8OID:
        type = QVariant::Double;
        break;
    case BOOLOID:
        type = QVariant::Bool;
        break;
    case CHAROID:
        type = QVariant::Char;
        break;
    case DATEOID:
        type = QVariant::Date;
        break;
    case TIMEOID:
        type = QVariant::Time;
        break;
    case TIMESTAMPOID:
    case TIMESTAMPTZOID:
        type = QVariant::DateTime;
        break;
    case BYTEAOID:
        type = QVariant::ByteArray;
        break;
    default:
        type = QVariant::String;
        break;
    }
    return type;
}

QVariant raw2Variant(const char *val, QVariant::Type type)
{
    QVariant resValue;
    if (!val)
        resValue = QVariant();
    else
    {
        switch (type) {
        case QVariant::Bool:
            resValue = QVariant((bool)(val[0] == 't'));
            break;
        case QVariant::LongLong:
            if (val[0] == '-')
                resValue = QString::fromLatin1(val).toLongLong();
            else
                resValue = QString::fromLatin1(val).toULongLong();
            break;
        case QVariant::Int:
            resValue = atoi(val);
            break;
        case QVariant::Double:
            resValue = QString::fromLatin1(val).toDouble();
            break;
        case QVariant::Date:
            if (val[0] == '\0')
                resValue = QVariant(QDate());
            else
                resValue = QVariant(QDate::fromString(QString::fromLatin1(val), Qt::ISODate));
            break;
        case QVariant::Time: {
            const QString str = QString::fromLatin1(val);
            if (str.isEmpty())
                resValue = QVariant(QTime());
            else
                resValue = QVariant(QTime::fromString(str, Qt::ISODate));
            break;
        }
        case QVariant::DateTime: {
            QString dtval = QString::fromLatin1(val);
            if (dtval.length() < 10)
                resValue = QVariant(QDateTime());
            else
            {
                // milliseconds are sometimes returned with 2 digits only
                if (dtval.at(dtval.length() - 3).isPunct())
                    dtval += QLatin1Char('0');
                if (dtval.isEmpty())
                    resValue = QVariant(QDateTime());
                else
                    resValue = QVariant(QDateTime::fromString(dtval, Qt::ISODate));
            }
            break;
        }
        case QVariant::ByteArray: {
            auto data = pg::unescape_bytea(val);
            resValue = QVariant(QByteArray(reinterpret_cast<char*>(data.data()), data.size()));
            break;
        }
        default:
            resValue = QString::fromUtf8(val);
            break;
        }
    }

    return resValue;
}

params &operator<<(params &obj, const QString &param)
{
    if (param.isNull())
        return obj.add(nullptr);
    return obj.add(param.toStdString());
}

params &operator<<(params &obj, const QVariant &param)
{
    if (param.isNull() || !param.isValid())
        return obj.add(nullptr);

    QString resValue;
    switch (param.type())
    {
    case QVariant::DateTime:
        if (param.toDateTime().isValid())
            resValue = param.toDateTime().toString(QLatin1String("yyyy-MM-ddTHH:mm:ss.zzzt"));
        break;
    case QVariant::Time:
        if (param.toTime().isValid())
            resValue = param.toTime().toString(QLatin1String("HH:mm:ss.zzzt"));
        break;
    case QVariant::Date:
        if (param.toDate().isValid())
            resValue = param.toDate().toString(QLatin1String("yyyy-MM-dd"));
        break;
    case QVariant::String:
        resValue = param.toString();
        break;
    case QVariant::Bool:
        if (param.toBool())
            resValue = QLatin1String("true");
        else
            resValue = QLatin1String("false");
        break;
    case QVariant::ByteArray: {
        QByteArray ba(param.toByteArray());
        // TODO:  apply connection knowledge to use PQescapeByteaConn
        //        instead of PQescapeBytea (then we must have connection in connected state!)
        //        OR
        //        replace pg::escape_bytea with content of PQescapeByteaInternal with good params
        //        (std_strings = true, use_hex = true)
        resValue = QString::fromStdString(pg::escape_bytea(reinterpret_cast<const unsigned char*>(ba.constData()), ba.size()));
        break;
    }
    case QVariant::Double: {
        double val = param.toDouble();
        if (std::isnan(val))
            resValue = QLatin1String("NaN");
        else {
            int res = std::isinf(val);
            if (res == 1)
                resValue = QLatin1String("Infinity");
            else if (res == -1)
                resValue = QLatin1String("-Infinity");
            else
                resValue = QString::number(val);
        }
        break;
    }
    default:
        resValue = param.toString();
        break;
    }
    return obj.add(resValue.isNull() ? nullptr : resValue.toStdString());
}

params &operator<<(params &obj, const QJsonValue &param)
{
    if (param.isNull() || param.isUndefined())
        return obj.add(nullptr);
    return obj << param.toVariant();
}

bool isNumericType(unsigned int sqlType) noexcept
{
    switch (sqlType)
    {
    case INT2OID:
    case INT4OID:
    case INT8OID:
    case OIDOID:
    case TIDOID:
    case XIDOID:
    case CIDOID:
    case FLOAT4OID:
    case FLOAT8OID:
    case NUMERICOID:
        return true;
    }
    return false;
}

bool isUnquotedType(unsigned int sqlType) noexcept
{
    return (sqlType == BOOLOID || isNumericType(sqlType));
}

params &operator<<(params &obj, const int param)
{
    return obj << QVariant(param);
}

} // namespace pg
