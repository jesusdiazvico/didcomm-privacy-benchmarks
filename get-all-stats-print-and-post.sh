#!/bin/bash

cp results-enc.png flask-app/static
cp results-dec.png flask-app/static
cp results-size.png flask-app/static

flask run --host=0.0.0.0
