---
title: Install
---
{% capture readme %}{% include_relative README.md %}{% endcapture %}
{% assign section = readme | split: "## Installation" | last | split: "## For AI agents" | first | replace: ".md)", ".html)" %}
# Install

{{ section }}
