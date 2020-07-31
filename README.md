captive-portal
==============

A captive portal service for the thingy

Quick Start
-----------

### Prerequisites

 *  pipenv

### Development

Install all the dependencies:

```
INTERFACE=wlan0 pipenv install --dev
```

Run the dev server:

```
pipenv run dev
```

**WARNING:** the development server does not gracefully exit the app. This
leads to processes not killed and interface not shut down on exit.

Use this command instead:

```
pipenv run prod --host localhost --port 8000 --debug wlan0
```
