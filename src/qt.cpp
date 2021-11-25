#include "pgpp/qt.h"
#include "pgpp/connection.h"
#include "pgpp/types.h"
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
#include <cmath>

namespace pg
{

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
                resValue = QVariant(QTime::fromString(str, Qt::ISODateWithMs));
            break;
        }
        case QVariant::DateTime: {
            QString dtval = QString::fromLatin1(val);
            if (dtval.length() < 10)
                resValue = QVariant(QDateTime());
            else
            {
                // milliseconds are sometimes returned with 2 digits only
                //if (dtval.at(dtval.length() - 3).isPunct())
                //    dtval += QLatin1Char('0');
                if (dtval.isEmpty())
                    resValue = QVariant(QDateTime());
                else
                {
                    auto tmp = QDateTime::fromString(dtval, Qt::ISODateWithMs);
                    // enable time zone output (if it exists) and switch it to local
                    if (tmp.timeSpec() != Qt::LocalTime)
                    {
                        tmp = tmp.toLocalTime();
                        tmp.setOffsetFromUtc(tmp.offsetFromUtc());
                    }
                    resValue = tmp;
                }
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
            resValue = param.toDateTime().toString(Qt::ISODateWithMs);
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
