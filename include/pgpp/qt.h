#ifndef PG_QT_H
#define PG_QT_H

#include <QVariant>
#include "pgpp/params.h"

namespace pg
{

void changePassword();
bool changeSettings();
bool prepareDB(bool override = false);
QVariant::Type typeToVariantType(unsigned int sqlType);
QVariant raw2Variant(const char *val, QVariant::Type type);
params& operator<<(params& obj, const QString &param);
params& operator<<(params& obj, const QVariant &param);
params& operator<<(params& obj, const int param);
params& operator<<(params& obj, const QJsonValue &param);
bool isNumericType(unsigned int sqlType) noexcept;
bool isUnquotedType(unsigned int sqlType) noexcept;

} // namespace pg

#endif // PG_QT_H
