FROM git.triopsi.dev:5050/triopsi/gitlab-ci-pipeline-php:8.2

# Switch user to root
USER root
    
# Install Starship prompt
RUN curl -sSL https://starship.rs/install.sh | sh -s - --yes
RUN echo 'eval "$(starship init bash)"' >> /home/php/.bashrc
RUN mkdir -p /home/php/.config && touch /home/php/.config/starship.toml
RUN mkdir -p /home/php/.cache
RUN chown -R php:php /home/php

# Switch back to non-root user
USER php

# Configurate Starship prompt
RUN starship preset no-nerd-font -o ~/.config/starship.toml

# Configurate Starship prompt
RUN starship config command_timeout 2000

# Git sicherer Zugriff
RUN git config --global --add safe.directory /var/www/html