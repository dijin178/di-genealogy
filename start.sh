#!/bin/bash
# 解压数据库
if [ -f di_genealogy.db.gz ]; then
  gunzip -f di_genealogy.db.gz
fi
# 启动
exec gunicorn app:app --bind 0.0.0.0:$PORT --workers 2
