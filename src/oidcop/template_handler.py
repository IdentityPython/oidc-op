class TemplateHandler(object):
    def __init__(self):
        pass

    def render(self, template, **kwargs):
        raise NotImplementedError()


class Jinja2TemplateHandler(TemplateHandler):
    def __init__(self, template_env):
        self.template_env = template_env

    def render(self, template, **kwargs):
        template = self.template_env.get_template(template)

        return template.render(**kwargs)
